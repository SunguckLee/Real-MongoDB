// Copyright 2014 Damjan Cvetko. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package pcapgo

import (
	"bytes"
	"testing"
	"time"
)

// test header read
func TestCreatePcapReader(t *testing.T) {
	test := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	buf := bytes.NewBuffer(test)
	_, err := NewReader(buf)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

// test big endian file read
func TestCreatePcapReaderBigEndian(t *testing.T) {
	test := []byte{
		0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	}
	buf := bytes.NewBuffer(test)
	_, err := NewReader(buf)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

// test opening invalid data
func TestCreatePcapReaderFail(t *testing.T) {
	test := []byte{
		0xd0, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	buf := bytes.NewBuffer(test)
	_, err := NewReader(buf)
	if err == nil {
		t.Error("Should fail but did not")
		t.FailNow()
	}
}

func TestPacket(t *testing.T) {
	test := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, // magic, maj, min
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tz, sigfigs
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen, linkType
		0x5A, 0xCC, 0x1A, 0x54, 0x01, 0x00, 0x00, 0x00, // sec, usec
		0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // cap len, full len
		0x01, 0x02, 0x03, 0x04, // data
	}

	buf := bytes.NewBuffer(test)
	r, err := NewReader(buf)

	data, ci, err := r.ReadPacketData()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !ci.Timestamp.Equal(time.Date(2014, 9, 18, 12, 13, 14, 1000, time.UTC)) {
		t.Error("Invalid time read")
		t.FailNow()
	}
	if ci.CaptureLength != 4 || ci.Length != 8 {
		t.Error("Invalid CapLen or Len")
	}
	want := []byte{1, 2, 3, 4}
	if !bytes.Equal(data, want) {
		t.Errorf("buf mismatch:\nwant: %+v\ngot:  %+v", want, data)
	}
}

func TestPacketNano(t *testing.T) {
	test := []byte{
		0x4d, 0x3c, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, // magic, maj, min
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tz, sigfigs
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen, linkType
		0x5A, 0xCC, 0x1A, 0x54, 0x01, 0x00, 0x00, 0x00, // sec, usec
		0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // cap len, full len
		0x01, 0x02, 0x03, 0x04, // data
	}

	buf := bytes.NewBuffer(test)
	r, err := NewReader(buf)

	data, ci, err := r.ReadPacketData()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !ci.Timestamp.Equal(time.Date(2014, 9, 18, 12, 13, 14, 1, time.UTC)) {
		t.Error("Invalid time read")
		t.FailNow()
	}
	if ci.CaptureLength != 4 || ci.Length != 8 {
		t.Error("Invalid CapLen or Len")
	}
	want := []byte{1, 2, 3, 4}
	if !bytes.Equal(data, want) {
		t.Errorf("buf mismatch:\nwant: %+v\ngot:  %+v", want, data)
	}
}
