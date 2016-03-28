function nf5PktDecode(msg,rinfo) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12),
        sequence: msg.readUInt32BE(16),
        engine_type: msg.readUInt8(20),
        engine_id: msg.readUInt8(21),
        sampling_interval: msg.readUInt16BE(22)
    }, flows: []};
    var buf = msg.slice(24);
    var t;
    while(buf.length>0) {
        out.flows.push({
            ipv4_src_addr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_dst_addr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_next_hop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input_snmp: buf.readUInt16BE(12),
            output_snmp: buf.readUInt16BE(14),
            in_pkts: buf.readUInt32BE(16),
            in_bytes: buf.readUInt32BE(20),
            first_switched: buf.readUInt32BE(24),
            last_switched: buf.readUInt32BE(28),
            ipv4_src_port: buf.readUInt16BE(32),
            ipv4_dst_port: buf.readUInt16BE(34),
            tcp_flags: buf.readUInt8(37),
            protocol: buf.readUInt8(38),
            src_tos: buf.readUInt8(39),
            in_as: buf.readUInt16BE(40),
            out_as: buf.readUInt16BE(42),
            src_mask: buf.readUInt8(44),
            dst_mask: buf.readUInt8(45)
        });
        buf = buf.slice(48);
    }
    return out;
}


module.exports = nf5PktDecode;