/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trzsz/tsshd/tsshd"
)

func TestParseTsshdPortRanges(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parseTsshdPortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parseTsshdPortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parseTsshdPortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parseTsshdPortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parseTsshdPortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parseTsshdPortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parseTsshdPortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parseTsshdPortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parseTsshdPortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parseTsshdPortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges(""))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parseTsshdPortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parseTsshdPortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parseTsshdPortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parseTsshdPortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parseTsshdPortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parseTsshdPortRanges("10 - 11 -"))
}

func TestUdpAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name, advertised, config string
		flag4, flag6, ssh4, ssh6 bool
		want4, want6, wantErr    bool
	}{
		{name: "ControlPathIPv6", advertised: "inet6", want6: true},
		{name: "ControlPathIPv4", advertised: "inet", want4: true},
		{name: "AttachOverIPv4", advertised: "inet6", ssh4: true, want6: true},
		{name: "AttachOverIPv6", advertised: "inet", ssh6: true, want4: true},
		{name: "OldServerInferred", ssh6: true, want6: true},
		{name: "OldServerUnknown"},
		{name: "OldServerAmbiguous", ssh4: true, ssh6: true},
		{name: "FutureUnknownFamily", advertised: "future", ssh4: true, want4: true},
		{name: "ExplicitOverridesSSH", flag4: true, ssh6: true, want4: true},
		{name: "ExplicitMatches", flag6: true, advertised: "inet6", ssh4: true, want6: true},
		{name: "ExplicitMismatch4", flag4: true, advertised: "inet6", wantErr: true},
		{name: "ExplicitMismatch6", flag6: true, advertised: "inet", wantErr: true},
		{name: "ConfigInet", config: "inet", ssh6: true, want4: true},
		{name: "ConfigInet6", config: "INET6", ssh4: true, want6: true},
		{name: "ConfigMismatch", config: "inet6", advertised: "inet", wantErr: true},
		{name: "ConfigAny", config: "any", advertised: "inet6", want6: true},
		{name: "FlagOverridesConfig", flag4: true, config: "inet6", advertised: "inet", want4: true},
		{name: "BothFlagsUnrestricted", flag4: true, flag6: true, advertised: "inet6", want6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config == "" {
				tc.config = "any"
			}
			args := &sshArgs{IPv4Only: tc.flag4, IPv6Only: tc.flag6,
				Option: sshOption{options: map[string][]string{"addressfamily": {tc.config}}}}
			param := &sshParam{args: args, ipv4: tc.ssh4, ipv6: tc.ssh6, host: "private.example", controlClient: true}
			info := &tsshd.ServerInfo{AddressFamily: tc.advertised}
			ipv4, ipv6, err := getUdpAddressFamily(param, info)
			if tc.wantErr {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), "conflicts with tsshd listener")
				}
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want4, ipv4)
			assert.Equal(t, tc.want6, ipv6)
			assert.Equal(t, "private.example", param.host)
		})
	}
}

func TestUdpAddressFamilyPerHop(t *testing.T) {
	args := &sshArgs{Option: sshOption{options: map[string][]string{"addressfamily": {"any"}}}}
	jump := &sshParam{args: args, host: "jump.example", ipv6: true}
	target := &sshParam{args: args, host: "internal.example", proxy: &proxyJump{name: jump.host}, ipv4: true}
	for _, hop := range []struct {
		param  *sshParam
		family string
		want4  bool
	}{
		{jump, "inet", true}, {target, "inet6", false},
	} {
		ipv4, ipv6, err := getUdpAddressFamily(hop.param, &tsshd.ServerInfo{AddressFamily: hop.family})
		assert.NoError(t, err)
		assert.Equal(t, hop.want4, ipv4)
		assert.Equal(t, !hop.want4, ipv6)
	}
	assert.Equal(t, "internal.example", target.host)
}

func TestUdpAddressFamilyControlPathLoopback(t *testing.T) {
	listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	address := net.JoinHostPort("localhost", strconv.Itoa(port))
	oldAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil || oldAddr.IP.To4() == nil {
		t.Skip("localhost needs an IPv4 record")
	}
	if _, err := net.ResolveUDPAddr("udp6", address); err != nil {
		t.Skip("localhost needs an IPv6 record")
	}
	go func() {
		buf := make([]byte, 32)
		for {
			n, peer, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = listener.WriteToUDP(buf[:n], peer)
		}
	}()
	// OpenSSH ControlPath exposes no TCP address family to the client.
	param := &sshParam{args: &sshArgs{Option: sshOption{options: map[string][]string{"addressfamily": {"any"}}}},
		host: "localhost", controlClient: true}
	for _, metadata := range []string{`{}`, `{"AddressFamily":"inet6"}`} {
		var info tsshd.ServerInfo
		if err := json.Unmarshal([]byte(metadata), &info); err != nil {
			t.Fatal(err)
		}
		ipv4, ipv6, err := getUdpAddressFamily(param, &info)
		if err != nil {
			t.Fatal(err)
		}
		network := "udp"
		if ipv4 {
			network = "udp4"
		} else if ipv6 {
			network = "udp6"
		}
		addr, err := net.ResolveUDPAddr(network, joinHostPort(param.host, strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialUDP(network, nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = conn.Write([]byte("family"))
		if err == nil {
			_, err = conn.Read(make([]byte, 32))
		}
		_ = conn.Close()
		if (info.AddressFamily != "") != (err == nil) {
			t.Fatalf("metadata=%s network=%s resolved=%s: %v", metadata, network, addr, err)
		}
	}
}
