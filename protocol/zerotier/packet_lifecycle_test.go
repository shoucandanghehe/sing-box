//go:build with_zerotier && with_gvisor

package zerotier

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestEndpointCloseDrainsOutboundWithoutConsumer(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45})})
	defer func() {
		for packet.ReadRefs() > 0 {
			packet.DecRef()
		}
	}()
	var packets stack.PacketBufferList
	packets.PushBack(packet)

	sent, err := (*ztLinkEndpoint)(ep).WritePackets(packets)
	if err != nil || sent != 1 {
		t.Fatalf("WritePackets() = (%d, %v), want (1, nil)", sent, err)
	}
	if refs := packet.ReadRefs(); refs != 2 {
		t.Fatalf("queued packet refs = %d, want 2", refs)
	}
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if queued := len(ep.outbound); queued != 0 {
		t.Fatalf("Close left %d outbound packets queued", queued)
	}
	if refs := packet.ReadRefs(); refs != 1 {
		t.Fatalf("Close left queued packet reference: refs=%d", refs)
	}
}

func TestZtLinkEndpointRejectsPacketsAfterClose(t *testing.T) {
	ep := newTestEndpoint(t, nil)
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}

	var admitted int
	for range 64 {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45})})
		var packets stack.PacketBufferList
		packets.PushBack(packet)
		sent, err := (*ztLinkEndpoint)(ep).WritePackets(packets)
		admitted += sent
		if _, ok := err.(*tcpip.ErrClosedForSend); !ok {
			packet.DecRef()
			t.Fatalf("WritePackets error = %T %v, want ErrClosedForSend", err, err)
		}
		if refs := packet.ReadRefs(); refs != 1 {
			for packet.ReadRefs() > 0 {
				packet.DecRef()
			}
			t.Fatalf("rejected packet refs = %d, want 1", refs)
		}
		packet.DecRef()
	}
	if admitted != 0 {
		t.Fatalf("WritePackets admitted %d packets after Close", admitted)
	}
	if queued := len(ep.outbound); queued != 0 {
		t.Fatalf("WritePackets queued %d packets after Close", queued)
	}
}
