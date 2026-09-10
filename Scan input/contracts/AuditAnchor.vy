# @version 0.4.3
"""
@title AuditAnchor
@notice Ye contract sirf ek kaam karta hai: ek hash (jaise SHA-256 of your
    alerts/policies history) ko on-chain "anchor" karna — timestamp aur
    sender ke saath, permanently. Actual alert/policy DATA yahan kabhi
    nahi jaata, sirf uska fingerprint. Isse tamper-evidence milta hai:
    agar baad mein koi purana alert record edit kare, uska hash badal
    jaayega aur on-chain anchored hash se match nahi karega — proof ki
    kuch tamper hua hai.
@dev Bahut simple by design — koi upgrade-ability, koi access control
    beyond msg.sender tracking, koi complex state. Ek append-only log.
"""

event Anchored:
    id: indexed(uint256)
    content_hash: indexed(bytes32)
    label: String[128]
    timestamp: uint256
    sender: address


struct Anchor:
    content_hash: bytes32
    label: String[128]
    timestamp: uint256
    sender: address


anchors: public(HashMap[uint256, Anchor])
anchor_count: public(uint256)

# content_hash -> anchor id (0 means "not found", so real ids start at 1)
hash_to_id: public(HashMap[bytes32, uint256])


@deploy
def __init__():
    self.anchor_count = 0


@external
def anchor(content_hash: bytes32, label: String[128]) -> uint256:
    """Anchors a new content hash. Returns the anchor's id.
    Re-anchoring the exact same hash is allowed (e.g. re-confirming
    nothing changed) but returns a NEW id each time — every anchor call
    is its own permanent, timestamped record."""
    new_id: uint256 = self.anchor_count + 1
    self.anchors[new_id] = Anchor(
        content_hash=content_hash,
        label=label,
        timestamp=block.timestamp,
        sender=msg.sender,
    )
    self.hash_to_id[content_hash] = new_id
    self.anchor_count = new_id

    log Anchored(id=new_id, content_hash=content_hash, label=label, timestamp=block.timestamp, sender=msg.sender)
    return new_id


@view
@external
def get_anchor(id: uint256) -> Anchor:
    return self.anchors[id]


@view
@external
def verify(content_hash: bytes32) -> uint256:
    """Returns the id of the most recent anchor matching this hash, or 0
    if it was never anchored. A non-zero return is proof this exact
    content existed on-chain at anchors[id].timestamp."""
    return self.hash_to_id[content_hash]
