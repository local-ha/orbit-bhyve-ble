# Archived RX-keystream brutes (historical)

These two tools were used to crack the device→host (RX) keystream. **RX is solved**, so
they are kept only as a record of the search — they are not part of the active toolset.

- `rx_joint_brute.py` — the tool that cracked it. A batched-AES joint search requiring all
  RX frames of a session to decode under one IV with a single advancing counter.
- `find_rx_keystream.py` — the earlier offline brute over structured IV candidates; it
  correctly ruled out an IV rearrangement but never reached the true RX counter base.

## The answer they found

RX uses the **same IV as TX** (`rx_response[:4] || init_tx[4:12]`) with a **separate counter
base** `counter_RX = uint32_LE(init_tx[16:20])` (the last 4 init bytes, long mislabeled
"reserved"). The RX base sits ~667M away from the TX base, which is why earlier counter
windows missed it. See `docs/encryption.md` and `docs/ble_protocol.md`.

## Running them now

They were written against the old flat layout and import `bhyve`, `decode_frame`, and
`extract_capture` from the parent directory. From `archive/` those imports no longer resolve
unchanged; if you need to re-run one for the record, run it from `scripts/exploration/` (e.g.
`python archive/rx_joint_brute.py`) and/or pass `CAP=` to point at a capture. They are not
maintained.
