"""AI Security Analyst: deterministic evidence + optional real LLM analysis.

The deterministic engine remains authoritative for detection and risk scoring.
When OPENAI_API_KEY is configured, this module sends a compact, redacted security
snapshot to the OpenAI Responses API and uses the model only for explanation,
prioritization, correlation, and analyst recommendations. No enforcement is
performed by the model.
"""
import hashlib, json, os
from datetime import datetime, timezone
from collections import Counter
import alert_agent

try:
    from dotenv import load_dotenv
    _HERE = os.path.dirname(os.path.abspath(__file__))
    _PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
    # The backend is normally launched from "Scan input", while the .env file
    # belongs at the project root. Load both locations explicitly.
    load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))
    load_dotenv(os.path.join(_HERE, ".env"), override=False)
except Exception:
    pass


def _stable_incident_key(incident):
    types=",".join(sorted({a.risk_type for a in incident.alerts}))
    raw=f"{incident.src_ip}|{types}|{incident.first_ts.isoformat()[:16]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12].upper()


def _policy_for_incident(incident, policies):
    for alert in incident.alerts:
        cid=alert.conn_id or alert.flow_id or alert.alert_id
        for p in policies:
            if p.get("policy_id")==f"POL-{cid}": return p
    return None


def _risk_score(incident):
    sev={"CRITICAL":100,"HIGH":80,"MEDIUM":55,"LOW":30,"INFO":10}
    levels=[sev.get(a.risk_level,30) for a in incident.alerts]
    conf=sum(a.confidence_score for a in incident.alerts)/max(1,len(incident.alerts))
    base=max(levels) if levels else 0
    velocity=min(15,max(0,len(incident.alerts)-1)*5)
    return min(100,round(base*.65+conf*100*.25+velocity))


def _recommended_actions(incident, policy, device):
    actions=[]; types={a.risk_type for a in incident.alerts}
    if "PORT_SCANNING" in types: actions.append("Validate the source and inspect the targeted service before containment.")
    if "CROSS_SEGMENT_ACCESS" in types: actions.append("Review the segment path and restrict the low-trust source from the protected asset.")
    if "UNEXPECTED_SERVICE_ACCESS" in types: actions.append("Inspect the source process and confirm whether the administrative service is expected.")
    if "FAN_OUT_LATERAL_MOVEMENT" in types: actions.append("Compare new destinations with the learned baseline before taking action.")
    if not actions: actions.append("Review the evidence and confirm whether the observed behavior is authorized.")
    if device and device.get("alert_count",0)>0: actions.append("Open the source asset profile and review recent ports, processes and connections.")
    if policy: actions.append(f"Human review required before applying the suggested {policy.get('action','BLOCK')} policy.")
    return actions[:5]


def build_incidents(alerts, policies, devices):
    incidents=alert_agent.correlate_alerts(alerts); device_map={d.get('ip'):d for d in devices}; output=[]
    for incident in incidents:
        policy=_policy_for_incident(incident,policies); device=device_map.get(incident.src_ip)
        types=list(dict.fromkeys(a.risk_type for a in incident.alerts))
        highest=max(incident.alerts,key=lambda a:alert_agent.RISK_LEVEL_SCORE.get(a.risk_level,1.0))
        evidence=[{"alert_id":a.alert_id,"risk_type":a.risk_type,"risk_level":a.risk_level,"confidence":a.confidence_score,"src_ip":a.src_ip,"dst_ip":a.dst_ip,"process":a.raw_data.get('src_process'),"dst_port":a.raw_data.get('dst_port'),"evidence":a.raw_data.get('evidence',''),"timestamp":a.timestamp.isoformat()} for a in incident.alerts]
        output.append({"incident_id":incident.incident_id,"incident_key":_stable_incident_key(incident),"src_ip":incident.src_ip,"first_seen":incident.first_ts.isoformat(),"last_seen":incident.last_ts.isoformat(),"alert_count":len(incident.alerts),"risk_types":types,"severity":highest.risk_level,"priority_score":alert_agent.prioritize(incident),"risk_score":_risk_score(incident),"summary":f"{', '.join(t.replace('_',' ').title() for t in types)} detected from {incident.src_ip}; {len(incident.alerts)} related event(s) were correlated.","evidence":evidence,"asset":device,"policy":policy,"recommended_actions":_recommended_actions(incident,policy,device)})
    output.sort(key=lambda x:x['priority_score'],reverse=True); return output


def build_overview(incidents,devices):
    counts=Counter(t for i in incidents for t in i['risk_types']); high=sum(1 for i in incidents if i['severity'] in {'HIGH','CRITICAL'}); top=max(devices,key=lambda d:d.get('risk_score',0),default=None)
    if not incidents: summary="No active incidents are currently supported by the deterministic risk engine. Continue observing the network baseline."; posture="NORMAL"
    elif high: summary=f"{len(incidents)} active incident(s) require analyst review; {high} are high or critical severity."; posture="ATTENTION"
    else: summary=f"{len(incidents)} active incident(s) detected; none are currently critical or high severity."; posture="MONITOR"
    return {"posture":posture,"summary":summary,"active_incidents":len(incidents),"high_or_critical":high,"risk_type_counts":dict(counts),"top_risk_asset":top,"generated_at":datetime.now(timezone.utc).isoformat()}


def _compact_context(overview,incidents,devices,connections,policies):
    # Keep the model input small and avoid sending unnecessary telemetry.
    return {"overview":overview,"incidents":[{"id":i['incident_key'],"severity":i['severity'],"risk_score":i['risk_score'],"source":i['src_ip'],"types":i['risk_types'],"summary":i['summary'],"evidence":i['evidence'][:5],"asset":{k:i['asset'].get(k) for k in ('segment','device_type','risk_score','alert_count','active_connections') if i.get('asset') and k in i['asset']}} for i in incidents[:8]],"telemetry_summary":{"devices":len(devices),"connections":len(connections)},"policies":[{"id":p.get('policy_id'),"action":p.get('action'),"src":p.get('src_ip'),"dst":p.get('dst_ip'),"status":p.get('status')} for p in policies[:10]]}


def _fallback_ai(overview,incidents):
    if not incidents:
        return {"headline":"No active incident requires escalation","assessment":"The deterministic detection pipeline currently reports no active correlated incident.","why_it_matters":"Continue baseline observation so new deviations can be distinguished from normal behavior.","actions":["Continue observing the baseline","Review new alerts as they appear"],"confidence":"LOW"}
    top=incidents[0]
    return {"headline":f"Prioritize {top['risk_types'][0].replace('_',' ').title()} from {top['src_ip']}","assessment":top['summary'],"why_it_matters":"The source is already associated with a detected security event; analyst review should establish whether the behavior is authorized before containment.","actions":top['recommended_actions'],"confidence":"MEDIUM","fallback":True}


def run_real_ai(overview,incidents,devices,connections,policies):
    key=os.getenv('OPENAI_API_KEY','').strip()
    if not key: return None, 'NOT_CONFIGURED'
    try:
        from openai import OpenAI
        client=OpenAI(api_key=key)
        model=os.getenv('OPENAI_MODEL','gpt-5.6-luna')
        context=json.dumps(_compact_context(overview,incidents,devices,connections,policies),separators=(',',':'))
        instructions=("You are a defensive SOC analyst. Analyze only the supplied telemetry. "
          "Do not invent facts. Separate observed evidence from inference. Prioritize incidents, "
          "explain why they matter, and give practical next steps. Never recommend destructive or "
          "unauthorized actions. The platform does not permit automatic enforcement. Return ONLY valid JSON "
          "with keys headline, assessment, why_it_matters, actions (array of 2-5 strings), confidence, "
          "and evidence_points (array of short strings).")
        resp=client.responses.create(model=model,instructions=instructions,input=context)
        text=(getattr(resp,'output_text','') or '').strip()
        data=json.loads(text)
        if not isinstance(data,dict): raise ValueError('Model returned non-object JSON')
        data['model']=model; data['provider']='OpenAI Responses API'; data['fallback']=False
        return data,'OPENAI'
    except Exception as exc:
        return {"error":f"Real AI unavailable: {type(exc).__name__}: {exc}"},'ERROR'


def generate_analysis(alerts,policies,devices,connections):
    incidents=build_incidents(alerts,policies,devices); overview=build_overview(incidents,devices)
    ai,provider=run_real_ai(overview,incidents,devices,connections,policies)
    if ai is None: ai=_fallback_ai(overview,incidents); provider='DETERMINISTIC_FALLBACK'
    return {"overview":overview,"incidents":incidents,"ai":ai,"provider":provider,"mode":"simulated","guardrail":"AI explains and prioritizes evidence; a human analyst makes the final enforcement decision."}
