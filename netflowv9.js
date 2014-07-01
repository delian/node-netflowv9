/**
 * Created by delian.
 */

var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');

function decNumber(buf,pos,len) {
    switch (len) {
        case 1:
            return buf.readUInt8(pos);
            break;
        case 2:
            return buf.readUInt16BE(pos);
            break;
        case 3:
            return buf.readUInt8(pos)*65536+buf.readUInt16BE(pos+1);
            break;
        case 4:
            return buf.readUInt32BE(pos);
            break;
        case 5:
            return buf.readUInt8(pos)*4294967296+buf.readUInt32BE(pos+1);
            break;
        case 6:
            return buf.readUInt16BE(pos)*4294967296+buf.readUInt32BE(pos+2);
            break;
        case 8:
            return buf.readUInt32BE(pos)*4294967296+buf.readUInt32BE(pos+4);
            break;
        default:
            console.log('Unknown len',len);
    }
    return 0;
}

function decIpv4Num(buf,pos,len) {
    var ip = buf.readUInt32BE(pos);
    return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
}

function decIpv6Num(buf,pos,len) {
    return buf.toString('hex',pos,pos+len);
}

function decEthMac(buf,pos,len) {
    return buf.toString('hex',pos,pos+len);
}

function decString(buf,pos,len) {
    return buf.toString('utf8',pos,pos+len);
}

var decNumRule = {
    1: "buf.readUInt8($pos)",
    2: "buf.readUInt16BE($pos)",
    3: "buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1)",
    4: "buf.readUInt32BE($pos)",
    5: "buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1)",
    6: "buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2)",
    8: "buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4)"
};

var decIpv6Rule = {
    16: "buf.toString('hex',$pos,$pos+$len)"
};

var decMacRule = {
    0: "buf.toString('hex',$pos,$pos+$len)"
};

var decStringRule = {
    0: "buf.toString('utf8',$pos,$pos+$len)"
};

var nfTypes = {
     '1': { name: 'in_bytes', len: 4, decode: decNumber, compileRule: decNumRule },
     '2': { name: 'in_pkts', len: 4, decode: decNumber, compileRule: decNumRule },
     '3': { name: 'flows', len: 4, decode: decNumber, compileRule: decNumRule },
     '4': { name: 'protocol', len: 1, decode: decNumber, compileRule: decNumRule },
     '5': { name: 'src_tos', len: 1, decode: decNumber, compileRule: decNumRule },
     '6': { name: 'tcp_flags', len: 1, decode: decNumber, compileRule: decNumRule },
     '7': { name: 'l4_src_port', len: 2, decode: decNumber, compileRule: decNumRule },
     '8': { name: 'ipv4_src_addr', len: 4, decode: decIpv4Num },
     '9': { name: 'src_mask', len: 1, decode: decNumber, compileRule: decNumRule },
    '10': { name: 'input_snmp', len: 2, decode: decNumber, compileRule: decNumRule },
    '11': { name: 'l4_dst_port', len: 2, decode: decNumber, compileRule: decNumRule },
    '12': { name: 'ipv4_dst_addr', len: 4, decode: decIpv4Num },
    '13': { name: 'dst_mask', len: 1, decode: decNumber, compileRule: decNumRule },
    '14': { name: 'output_snmp', len: 2, decode: decNumber, compileRule: decNumRule },
    '15': { name: 'ipv4_next_hop', len: 4, decode: decIpv4Num },
    '16': { name: 'src_as', len: 2, decode: decNumber, compileRule: decNumRule },
    '17': { name: 'dst_as', len: 2, decode: decNumber, compileRule: decNumRule },
    '18': { name: 'bgp_ipv4_next_hop', len: 4, decode: decIpv4Num },
    '19': { name: 'mul_dst_pkts', len: 4, decode: decNumber, compileRule: decNumRule },
    '20': { name: 'mul_dst_bytes', len: 4, decode: decNumber, compileRule: decNumRule },
    '21': { name: 'last_switched', len: 4, decode: decNumber, compileRule: decNumRule },
    '22': { name: 'first_switched', len: 4, decode: decNumber, compileRule: decNumRule },
    '23': { name: 'out_bytes', len: 4, decode: decNumber, compileRule: decNumRule },
    '24': { name: 'out_pkts', len: 4, decode: decNumber, compileRule: decNumRule },
    '25': { name: 'min_pkt_lngth', len: 2, decode: decNumber, compileRule: decNumRule },
    '26': { name: 'max_pkt_lngth', len: 2, decode: decNumber, compileRule: decNumRule },
    '27': { name: 'ipv6_src_addr', len: 16, decode: decIpv6Num, compileRule: decIpv6Rule },
    '28': { name: 'ipv6_dst_addr', len: 16, decode: decIpv6Num, compileRule: decIpv6Rule },
    '29': { name: 'ipv6_src_mask', len: 1, decode: decNumber, compileRule: decNumRule },
    '30': { name: 'ipv6_dst_mask', len: 1, decode: decNumber, compileRule: decNumRule },
    '31': { name: 'ipv6_flow_label', len: 3, decode: decNumber, compileRule: decNumRule },
    '32': { name: 'icmp_type', len: 2, decode: decNumber, compileRule: decNumRule },
    '33': { name: 'mul_igmp_type', len: 1, decode: decNumber, compileRule: decNumRule },
    '34': { name: 'sampling_interval', len: 4, decode: decNumber, compileRule: decNumRule },
    '35': { name: 'sampling_algorithm', len: 1, decode: decNumber, compileRule: decNumRule },
    '36': { name: 'flow_active_timeout', len: 2, decode: decNumber, compileRule: decNumRule },
    '37': { name: 'flow_inactive_timeout', len: 2, decode: decNumber, compileRule: decNumRule },
    '38': { name: 'engine_type', len: 1, decode: decNumber, compileRule: decNumRule },
    '39': { name: 'engine_id', len: 1, decode: decNumber, compileRule: decNumRule },
    '40': { name: 'total_bytes_exp', len: 4, decode: decNumber, compileRule: decNumRule },
    '41': { name: 'total_pkts_exp', len: 4, decode: decNumber, compileRule: decNumRule },
    '42': { name: 'total_flows_exp', len: 4, decode: decNumber, compileRule: decNumRule },
    '44': { name: 'ipv4_src_prefix', len: 4, decode: decIpv4Num },
    '45': { name: 'ipv4_dst_prefix', len: 4, decode: decIpv4Num },
    '46': { name: 'mpls_top_label_type', len: 1, decode: decNumber },
    '47': { name: 'mpls_top_label_ip_addr', len: 4, decode: decIpv4Num },
    '48': { name: 'flow_sampler_id', len: 1, decode: decNumber, compileRule: decNumRule },
    '49': { name: 'flow_sampler_mode', len: 1, decode: decNumber, compileRule: decNumRule },
    '50': { name: 'flow_sampler_random_interval', len: 4, decode: decNumber, compileRule: decNumRule },
    '52': { name: 'min_ttl', len: 1, decode: decNumber, compileRule: decNumRule },
    '53': { name: 'max_ttl', len: 1, decode: decNumber, compileRule: decNumRule },
    '54': { name: 'ipv4_ident', len: 2, decode: decNumber, compileRule: decNumRule },
    '55': { name: 'dst_tos', len: 1, decode: decNumber, compileRule: decNumRule },
    '56': { name: 'in_src_mac', len: 6, decode: decEthMac, compileRule: decMacRule },
    '57': { name: 'out_dst_mac', len: 6, decode: decEthMac, compileRule: decMacRule },
    '58': { name: 'src_vlan', len: 2, decode: decNumber, compileRule: decNumRule },
    '59': { name: 'dst_vlan', len: 2, decode: decNumber, compileRule: decNumRule },
    '60': { name: 'ip_protocol_version', len: 1, decode: decNumber, compileRule: decNumRule },
    '61': { name: 'direction', len: 1, decode: decNumber, compileRule: decNumRule },
    '62': { name: 'ipv6_next_hop', len: 16, decode: decIpv6Num, compileRule: decIpv6Rule },
    '63': { name: 'bpg_ipv6_next_hop', len: 16, decode: decIpv6Num, compileRule: decIpv6Rule },
    '64': { name: 'ipv6_option_headers', len: 4, decode: decNumber, compileRule: decNumRule },
    '70': { name: 'mpls_label_1', len: 3, decode: decNumber, compileRule: decNumRule },
    '71': { name: 'mpls_label_2', len: 3, decode: decNumber, compileRule: decNumRule },
    '72': { name: 'mpls_label_3', len: 3, decode: decNumber, compileRule: decNumRule },
    '73': { name: 'mpls_label_4', len: 3, decode: decNumber, compileRule: decNumRule },
    '74': { name: 'mpls_label_5', len: 3, decode: decNumber, compileRule: decNumRule },
    '75': { name: 'mpls_label_6', len: 3, decode: decNumber, compileRule: decNumRule },
    '76': { name: 'mpls_label_7', len: 3, decode: decNumber, compileRule: decNumRule },
    '77': { name: 'mpls_label_8', len: 3, decode: decNumber, compileRule: decNumRule },
    '78': { name: 'mpls_label_9', len: 3, decode: decNumber, compileRule: decNumRule },
    '79': { name: 'mpls_label_10', len: 3, decode: decNumber, compileRule: decNumRule },
    '80': { name: 'in_dst_mac', len: 6, decode: decEthMac, compileRule: decMacRule },
    '81': { name: 'out_src_mac', len: 6, decode: decEthMac, compileRule: decMacRule },
    '82': { name: 'if_name', len: 2, decode: decString, compileRule: decStringRule },
    '83': { name: 'if_desc', len: 4, decode: decString, compileRule: decStringRule },
    '84': { name: 'sampler_name', len: 4, decode: decString, compileRule: decStringRule },
    '85': { name: 'in_permanent_bytes', len: 4, decode: decNumber, compileRule: decNumRule },
    '86': { name: 'in_permanent_pkts', len: 4, decode: decNumber, compileRule: decNumRule },
    '88': { name: 'fragment_offset', len: 2, decode: decNumber, compileRule: decNumRule },
    '89': { name: 'fw_status', len: 1, decode: decNumber, compileRule: decNumRule },
    '90': { name: 'mpls_pal_rd', len: 8, decode: decNumber, compileRule: decNumRule },
    '91': { name: 'mpls_prefix_len', len: 1, decode: decNumber, compileRule: decNumRule },
    '92': { name: 'src_traffic_index', len: 4, decode: decNumber, compileRule: decNumRule },
    '93': { name: 'dst_traffic_index', len: 4, decode: decNumber, compileRule: decNumRule },
    '94': { name: 'application_descr', len: 4, decode: decString, compileRule: decStringRule },
    '95': { name: 'application_tag', len: 4, decode: decEthMac, compileRule: decMacRule },
    '96': { name: 'application_name', len: 4, decode: decString, compileRule: decStringRule },
    '98': { name: 'DiffServCodePoint', len: 1, decode: decNumber, compileRule: decNumRule },
    '99': { name: 'replication_factor', len: 4, decode: decNumber, compileRule: decNumRule },
    '128': { name: 'in_as', len: 4, decode: decNumber, compileRule: decNumRule },
    '129': { name: 'out_as', len: 4, decode: decNumber, compileRule: decNumRule }
};

function nfPktDecode(msg,templates) {
    var out = { header: {}, flows: [] };
    out.header.version = msg.readUInt16BE(0);
    out.header.count = msg.readUInt16BE(2);
    out.header.uptime = msg.readUInt32BE(4);
    out.header.seconds = msg.readUInt32BE(8);
    out.header.sequence = msg.readUInt32BE(12);
    out.header.sourceId = msg.readUInt32BE(16);
    if (out.header.version!=9) {
        debug('bad header version %d', out.header.version);
        return;
    }

    function compileStatement(type,pos,len) {
        var nf = nfTypes[type];
        if (nf.compileRule) {
            if (nf.compileRule[len]) return nf.compileRule[len].toString().replace(/(\$pos)/g,function(n) { return pos }).replace(/(\$len)/g,function(n) { return len });
            if (nf.compileRule[0]) return nf.compileRule[0].toString().replace(/(\$pos)/g,function(n) { return pos }).replace(/(\$len)/g,function(n) { return len });
        }
        return "nfTypes['"+type+"'].decode(buf,"+pos+","+len+")";
    }

    function compileTemplate(list) {
        var i, z, nf, n;
        var f = "var o = {};\n";
        for (i=0,n=0;i<list.length;i++,n+=z.len) {
            z=list[i];
            nf = nfTypes[z.type];
            if (!nf) {
                console.log('Unknown NF type',z);
                throw new Error('Unknown NF Type');
            }
            f+="o['"+nf.name+"']="+compileStatement(z.type, n, z.len)+";\n";
        }
        f+="return o;\n";
        //console.log('The template will be compiled to',f);
        return new Function('buf','nfTypes',f);
    }

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        var len  = buffer.readUInt16BE(2);
        var buf = buffer.slice(4,len);
        while(buf.length>0) {
            var tId  = buf.readUInt16BE(0);
            var cnt  = buf.readUInt16BE(2);
            var list = [];
            var len = 0;
            for (var i = 0; i<cnt; i++) {
                list.push({ type: buf.readUInt16BE(4+4*i), len: buf.readUInt16BE(6+4*i) });
                len += buf.readUInt16BE(6+4*i);
            }

            templates[tId] = { len: len, list: list , compiled: compileTemplate(list) };
            buf = buf.slice(4+cnt*4);
        }
    }

    function decodeTemplate(fsId,buf) {
        var o = templates[fsId].compiled(buf,nfTypes);
        o.fsId = fsId;
        return o;
    }

    var buf = msg.slice(20);
    while(buf.length>0) {
        var fsId = buf.readUInt16BE(0);
        var len = buf.readUInt16BE(2);
        if (fsId==0) readTemplate(buf);
        if (typeof templates[fsId] != 'undefined') {
            var tbuf = buf.slice(4,len);
            while(tbuf.length>=templates[fsId].len) {
                out.flows.push(decodeTemplate(fsId,tbuf));
                tbuf = tbuf.slice(templates[fsId].len);
            }
        }
        buf = buf.slice(len);
    }
    
    return out;
}

function NetFlowV9(cb,flushPerPkt) {
    if (!(this instanceof NetFlowV9)) return new NetFlowV9(cb,flushPerPkt);
    var me = this;
    this.templates = {};
    this.server = dgram.createSocket('udp4');
    this.server.on('message',function(msg, rinfo) {
        //console.log('rinfo',rinfo);
        if (rinfo.size<20) return;
        var o = nfPktDecode(msg,me.templates);
        if (cb) {
            if (flushPerPkt)
            {
                o.rinfo = rinfo;
                o.packet = msg;
                cb(o);
            }
            else
            o.flows.forEach(function(n) {
                cb({
                    header: o.header,
                    rinfo: rinfo,
                    packet: msg,
                    flow: n
                });
            });
        }
    });
    this.listen = function(port) {
        var me = this;
        setTimeout(function() {
            me.server.bind(port);
        },50);
    };
}

NetFlowV9.nfPktDecode = nfPktDecode;

module.exports = NetFlowV9;
