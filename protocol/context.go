package protocol

// WrapContext ist der Kontext des DEK-Wraps.
//
//	L("dek-wrap") || "dek-wrap" || mandant_id || ablage_id || epoch_id || kek_fingerabdruck
func WrapContext(mandant, ablage ID, epoch EpochID, kek Hash) []byte {
	buf := make([]byte, 0, 4+8+IDLen+IDLen+EpochLen+HashLen)
	buf = AppendText(buf, "dek-wrap")
	buf = append(buf, mandant[:]...)
	buf = append(buf, ablage[:]...)
	buf = append(buf, epoch[:]...)
	buf = append(buf, kek[:]...)
	return buf
}

// BindungContext ist der Kontext des Wraps um den Bindungsschlüssel.
//
//	L("annahme-bindung") || "annahme-bindung" || mandant_id || batch_id || kek_fingerabdruck
func BindungContext(mandant, batch ID, kek Hash) []byte {
	buf := make([]byte, 0, 4+15+IDLen+IDLen+HashLen)
	buf = AppendText(buf, "annahme-bindung")
	buf = append(buf, mandant[:]...)
	buf = append(buf, batch[:]...)
	buf = append(buf, kek[:]...)
	return buf
}

// BindungAAD sind die Zusatzdaten der einmaligen AES-256-GCM-Verschlüsselung von bindung.
//
//	L("bindung-aad") || "bindung-aad" || mandant_id || batch_id || kek_fingerabdruck
func BindungAAD(mandant, batch ID, kek Hash) []byte {
	buf := make([]byte, 0, 4+11+IDLen+IDLen+HashLen)
	buf = AppendText(buf, "bindung-aad")
	buf = append(buf, mandant[:]...)
	buf = append(buf, batch[:]...)
	buf = append(buf, kek[:]...)
	return buf
}
