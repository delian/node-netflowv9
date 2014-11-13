/**
 * Created by delian on 11/11/14.
 * New version of the NetFlow V9 code
 * This version support only compiled code and works with streams API
 */

require('debug').enable('NetFlowV9');
var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');
var util = require('util');
var e = require('events').EventEmitter;

var decNumRule = {
    1: "o['$name']=buf.readUInt8($pos);",
    2: "o['$name']=buf.readUInt16BE($pos);",
    3: "o['$name']=buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1);",
    4: "o['$name']=buf.readUInt32BE($pos);",
    5: "o['$name']=buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1);",
    6: "o['$name']=buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2);",
    8: "o['$name']=buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4);"
};

var decIpv4Rule = {
    4: "o['$name']=(t=buf.readUInt32BE($pos),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256));"
};

var decIpv6Rule = {
    16: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decMacRule = {
    0: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decStringRule = {
    0: "o['$name']=buf.toString('utf8',$pos,$pos+$len);"
};

var nfTypes = {
    '1': {name: 'in_bytes', compileRule: decNumRule},
    '2': {name: 'in_pkts', compileRule: decNumRule},
    '3': {name: 'flows', compileRule: decNumRule},
    '4': {name: 'protocol', compileRule: decNumRule},
    '5': {name: 'src_tos', compileRule: decNumRule},
    '6': {name: 'tcp_flags', compileRule: decNumRule},
    '7': {name: 'l4_src_port', compileRule: decNumRule},
    '8': {name: 'ipv4_src_addr', compileRule: decIpv4Rule},
    '9': {name: 'src_mask', compileRule: decNumRule},
    '10': {name: 'input_snmp', compileRule: decNumRule},
    '11': {name: 'l4_dst_port', compileRule: decNumRule},
    '12': {name: 'ipv4_dst_addr', compileRule: decIpv4Rule},
    '13': {name: 'dst_mask', compileRule: decNumRule},
    '14': {name: 'output_snmp', compileRule: decNumRule},
    '15': {name: 'ipv4_next_hop', compileRule: decIpv4Rule},
    '16': {name: 'src_as', compileRule: decNumRule},
    '17': {name: 'dst_as', compileRule: decNumRule},
    '18': {name: 'bgp_ipv4_next_hop', compileRule: decIpv4Rule},
    '19': {name: 'mul_dst_pkts', compileRule: decNumRule},
    '20': {name: 'mul_dst_bytes', compileRule: decNumRule},
    '21': {name: 'last_switched', compileRule: decNumRule},
    '22': {name: 'first_switched', compileRule: decNumRule},
    '23': {name: 'out_bytes', compileRule: decNumRule},
    '24': {name: 'out_pkts', compileRule: decNumRule},
    '25': {name: 'min_pkt_lngth', compileRule: decNumRule},
    '26': {name: 'max_pkt_lngth', compileRule: decNumRule},
    '27': {name: 'ipv6_src_addr', compileRule: decIpv6Rule},
    '28': {name: 'ipv6_dst_addr', compileRule: decIpv6Rule},
    '29': {name: 'ipv6_src_mask', compileRule: decNumRule},
    '30': {name: 'ipv6_dst_mask', compileRule: decNumRule},
    '31': {name: 'ipv6_flow_label', compileRule: decNumRule},
    '32': {name: 'icmp_type', compileRule: decNumRule},
    '33': {name: 'mul_igmp_type', compileRule: decNumRule},
    '34': {name: 'sampling_interval', compileRule: decNumRule},
    '35': {name: 'sampling_algorithm', compileRule: decNumRule},
    '36': {name: 'flow_active_timeout', compileRule: decNumRule},
    '37': {name: 'flow_inactive_timeout', compileRule: decNumRule},
    '38': {name: 'engine_type', compileRule: decNumRule},
    '39': {name: 'engine_id', compileRule: decNumRule},
    '40': {name: 'total_bytes_exp', compileRule: decNumRule},
    '41': {name: 'total_pkts_exp', compileRule: decNumRule},
    '42': {name: 'total_flows_exp', compileRule: decNumRule},
    '44': {name: 'ipv4_src_prefix', compileRule: decIpv4Rule},
    '45': {name: 'ipv4_dst_prefix', compileRule: decIpv4Rule},
    '46': {name: 'mpls_top_label_type', compileRule: decIpv4Rule},
    '47': {name: 'mpls_top_label_ip_addr', compileRule: decIpv4Rule},
    '48': {name: 'flow_sampler_id', compileRule: decNumRule},
    '49': {name: 'flow_sampler_mode', compileRule: decNumRule},
    '50': {name: 'flow_sampler_random_interval', compileRule: decNumRule},
    '52': {name: 'min_ttl', compileRule: decNumRule},
    '53': {name: 'max_ttl', compileRule: decNumRule},
    '54': {name: 'ipv4_ident', compileRule: decNumRule},
    '55': {name: 'dst_tos', compileRule: decNumRule},
    '56': {name: 'in_src_mac', compileRule: decMacRule},
    '57': {name: 'out_dst_mac', compileRule: decMacRule},
    '58': {name: 'src_vlan', compileRule: decNumRule},
    '59': {name: 'dst_vlan', compileRule: decNumRule},
    '60': {name: 'ip_protocol_version', compileRule: decNumRule},
    '61': {name: 'direction', compileRule: decNumRule},
    '62': {name: 'ipv6_next_hop', compileRule: decIpv6Rule},
    '63': {name: 'bpg_ipv6_next_hop', compileRule: decIpv6Rule},
    '64': {name: 'ipv6_option_headers', compileRule: decNumRule},
    '70': {name: 'mpls_label_1', compileRule: decNumRule},
    '71': {name: 'mpls_label_2', compileRule: decNumRule},
    '72': {name: 'mpls_label_3', compileRule: decNumRule},
    '73': {name: 'mpls_label_4', compileRule: decNumRule},
    '74': {name: 'mpls_label_5', compileRule: decNumRule},
    '75': {name: 'mpls_label_6', compileRule: decNumRule},
    '76': {name: 'mpls_label_7', compileRule: decNumRule},
    '77': {name: 'mpls_label_8', compileRule: decNumRule},
    '78': {name: 'mpls_label_9', compileRule: decNumRule},
    '79': {name: 'mpls_label_10', compileRule: decNumRule},
    '80': {name: 'in_dst_mac', compileRule: decMacRule},
    '81': {name: 'out_src_mac', compileRule: decMacRule},
    '82': {name: 'if_name', compileRule: decStringRule},
    '83': {name: 'if_desc', compileRule: decStringRule},
    '84': {name: 'sampler_name', compileRule: decStringRule},
    '85': {name: 'in_permanent_bytes', compileRule: decNumRule},
    '86': {name: 'in_permanent_pkts', compileRule: decNumRule},
    '88': {name: 'fragment_offset', compileRule: decNumRule},
    '89': {name: 'fw_status', compileRule: decNumRule},
    '90': {name: 'mpls_pal_rd', compileRule: decNumRule},
    '91': {name: 'mpls_prefix_len', compileRule: decNumRule},
    '92': {name: 'src_traffic_index', compileRule: decNumRule},
    '93': {name: 'dst_traffic_index', compileRule: decNumRule},
    '94': {name: 'application_descr', compileRule: decStringRule},
    '95': {name: 'application_tag', compileRule: decMacRule},
    '96': {name: 'application_name', compileRule: decStringRule},
    '98': {name: 'DiffServCodePoint', compileRule: decNumRule},
    '99': {name: 'replication_factor', compileRule: decNumRule},
    //above 127 is in ipfix
    '128': {name: 'in_as', compileRule: decNumRule},
    '129': {name: 'out_as', compileRule: decNumRule},
    //the following are taken from from http://www.iana.org/assignments/ipfix/ipfix.xhtml
    '201': {name: 'mplsLabelStackLength', compileRule: decNumRule}
};

function nf9PktDecode(msg) {
    var templates = this.templates || {};
    var nfTypes = this.nfTypes || {};
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        sequence: msg.readUInt32BE(12),
        sourceId: msg.readUInt32BE(16)
    }, flows: [] };

    function compileStatement(type, pos, len) {
        var nf = nfTypes[type];
        var cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    function compileTemplate(list) {
        var i, z, nf, n;
        var f = "var o = {}; var t;\n";
        for (i = 0, n = 0; i < list.length; i++, n += z.len) {
            z = list[i];
            nf = nfTypes[z.type];
            if (!nf) {
                debug('Unknown NF type %d', z.type);
                throw new Error('Unknown NF Type');
            }
            f += compileStatement(z.type, n, z.len) + ";\n";
        }
        f += "return o;\n";
        debug('The template will be compiled to %s',f);
        return new Function('buf', 'nfTypes', f);
    }

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        var len = buffer.readUInt16BE(2);
        var buf = buffer.slice(4, len);
        while (buf.length > 0) {
            var tId = buf.readUInt16BE(0);
            var cnt = buf.readUInt16BE(2);
            var list = [];
            var len = 0;
            for (var i = 0; i < cnt; i++) {
                list.push({type: buf.readUInt16BE(4 + 4 * i), len: buf.readUInt16BE(6 + 4 * i)});
                len += buf.readUInt16BE(6 + 4 * i);
            }
            debug('compile template %s', tId);
            templates[tId] = {len: len, list: list, compiled: compileTemplate(list)};
            buf = buf.slice(4 + cnt * 4);
        }
    }

    function decodeTemplate(fsId, buf) {
        var o = templates[fsId].compiled(buf, nfTypes);
        o.fsId = fsId;
        return o;
    }

    var nfScope = {
        1: { name: 'scope_system', compileRule: decMacRule },
        2: { name: 'scope_interface', compileRule: decStringRule },
        3: { name: 'scope_linecard', compileRule: decNumRule },
        4: { name: 'scope_netflow_cache', compileRule: decNumRule },
        5: { name: 'scope_template', compileRule: decStringRule }
    };

    function compileScope(type,pos,len) {
        var nf = nfScope[type];
        var cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile scope rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    function readOptions(buffer) {
        var len = buffer.readUInt16BE(2);
        var tId = buffer.readUInt16BE(4);
        var osLen = buffer.readUInt16BE(6);
        var oLen = buffer.readUInt16BE(8);
        var buff = buffer.slice(10,len);
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d',len,tId,osLen,oLen,buff);
        var plen = 0;
        var cr = "var o={ isOption: true }; var t;\n";
        var type; var tlen;

        // Read the SCOPE
        var buf = buff.slice(0,osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    SCOPE type: %d (%s) len: %d, plen: %d', type,nfTypes[type].name,tlen,plen);
            if (type>0) cr+=compileScope(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type,nfTypes[type].name,tlen,plen);
            if (type>0) cr+=compileStatement(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }
        cr+="// option "+tId+"\n";
        cr+="return o;";
        debug('option template compiled to %s',cr);
        templates[tId] = { len: plen, compiled: new Function('buf','nfTypes',cr) };
    }

    var buf = msg.slice(20);
    while (buf.length > 0) {
        var fsId = buf.readUInt16BE(0);
        var len = buf.readUInt16BE(2);
        if (fsId == 0) readTemplate(buf);
        else if (fsId == 1) readOptions(buf);
        else if (fsId > 1 && fsId < 256) {
            debug('Unknown Flowset ID %d!', fsId);
        }
        else if (fsId > 255 && typeof templates[fsId] != 'undefined') {
            var tbuf = buf.slice(4, len);
            while (tbuf.length >= templates[fsId].len) {
                out.flows.push(decodeTemplate(fsId, tbuf));
                tbuf = tbuf.slice(templates[fsId].len);
            }
        } else if (fsId > 255) {
            debug('Unknown template/option data with flowset id %d',fsId);
        }
        buf = buf.slice(len);
    }

    return out;
}

function nf1PktDecode(msg) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12)
    }, flows: []};
    var buf = msg.slice(16);
    var t;
    while(buf.length>0) {
        out.flows.push({
            srcaddr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            dstaddr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            nexthop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input: buf.readUInt16BE(12),
            output: buf.readUInt16BE(14),
            dPkts: buf.readUInt32BE(16),
            dOctets: buf.readUInt32BE(20),
            first: buf.readUInt32BE(24),
            last: buf.readUInt32BE(28),
            srcport: buf.readUInt16BE(32),
            dstport: buf.readUInt16BE(34),
            prot: buf.readUInt8(38),
            tos: buf.readUInt8(39),
            tcp_flags: buf.readUInt8(40)
        });
        buf = buf.slice(48);
    }
    return out;
}

function nf5PktDecode(msg) {
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
            srcaddr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            dstaddr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            nexthop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input: buf.readUInt16BE(12),
            output: buf.readUInt16BE(14),
            dPkts: buf.readUInt32BE(16),
            dOctets: buf.readUInt32BE(20),
            first: buf.readUInt32BE(24),
            last: buf.readUInt32BE(28),
            srcport: buf.readUInt16BE(32),
            dstport: buf.readUInt16BE(34),
            tcp_flags: buf.readUInt8(37),
            prot: buf.readUInt8(38),
            tos: buf.readUInt8(39),
            src_as: buf.readUInt16BE(40),
            dst_as: buf.readUInt16BE(42),
            src_mask: buf.readUInt8(44),
            dst_mask: buf.readUInt8(45)
        });
        buf = buf.slice(48);
    }
    return out;
}

function nf7PktDecode(msg) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12),
        sequence: msg.readUInt32BE(16)
    }, flows: []};
    var buf = msg.slice(24);
    var t;
    while(buf.length>0) {
        out.flows.push({
            srcaddr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            dstaddr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            nexthop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input: buf.readUInt16BE(12),
            output: buf.readUInt16BE(14),
            dPkts: buf.readUInt32BE(16),
            dOctets: buf.readUInt32BE(20),
            first: buf.readUInt32BE(24),
            last: buf.readUInt32BE(28),
            srcport: buf.readUInt16BE(32),
            dstport: buf.readUInt16BE(34),
            flags: buf.readUInt8(36),
            tcp_flags: buf.readUInt8(37),
            prot: buf.readUInt8(38),
            tos: buf.readUInt8(39),
            src_as: buf.readUInt16BE(40),
            dst_as: buf.readUInt16BE(42),
            src_mask: buf.readUInt8(44),
            dst_mask: buf.readUInt8(45),
            flow_flags: buf.readUInt16BE(46),
            router_sc: (t=buf.readUInt32BE(48),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256))
        });
        buf = buf.slice(48);
    }
    return out;
}

function nfPktDecode(msg) {
    var version = msg.readUInt16BE(0);
    switch (version) {
        case 1:
            return this.nf1PktDecode(msg);
            break;
        case 5:
            return this.nf5PktDecode(msg);
            break;
        case 7:
            return this.nf7PktDecode(msg);
            break;
        case 9:
            return this.nf9PktDecode(msg);
            break;
        default:
            debug('bad header version %d', version);
            return;
    }
}

function NetFlowV9(options) {
    if (!(this instanceof NetFlowV9)) return new NetFlowV9(options);
    var me = this;
    this.templates = {};
    this.nfTypes = util._extend(nfTypes); // Inherit nfTypes
    if (options.ipv4num) decIpv4Rule[4] = "buf.readUInt32BE($pos)"; // TODO: Better code here!
    this.server = dgram.createSocket('udp4');
    e.call(this,options);
    this.server.on('message',function(msg,rinfo){
        if (rinfo.size<20) return;
        var o = me.nfPktDecode(msg);
        if (o && o.flows.length > 0) { // If the packet does not contain flows, only templates we do not decode
            o.rinfo = rinfo;
            o.packet = msg;
            me.emit('data',o);
        } else debug('Undecoded flows',o);
    });
    this.listen = function(port) {
        setTimeout(function() {
            me.server.bind(port);
        },50);
    };
    if (options.port) this.listen(options.port);
}

util.inherits(NetFlowV9,e);
NetFlowV9.prototype.nfPktDecode = nfPktDecode;
NetFlowV9.prototype.nf1PktDecode = nf1PktDecode;
NetFlowV9.prototype.nf5PktDecode = nf5PktDecode;
NetFlowV9.prototype.nf7PktDecode = nf7PktDecode;
NetFlowV9.prototype.nf9PktDecode = nf9PktDecode;

module.exports = NetFlowV9;