/**
 * Created by delian.
 */

var dgram = require('dgram');

function decNumber(buf,len) {
    switch (len) {
        case 1:
            return buf.readUInt8(0);
            break;
        case 2:
            return buf.readUInt16BE(0);
            break;
        case 3:
            return buf.readUInt8(0)*65536+buf.readUInt16BE(1);
            break;
        case 4:
            return buf.readUInt32BE(0);
            break;
        case 5:
            return buf.readUInt8(0)*4294967296+buf.readUInt32BE(1);
            break;
        case 6:
            return buf.readUInt16BE(0)*4294967296+buf.readUInt32BE(2);
            break;
        case 8:
            return buf.readUInt32BE(0)*4294967296+buf.readUInt32BE(4);
            break;
        default:
            console.log('Unknown len',len);
    }
    return 0;
}

var nfTypes = {
     '1': { name: 'in_bytes', len: 4, decode: decNumber },
     '2': { name: 'in_pkts', len: 4, decode: decNumber },
     '3': { name: 'flows', len: 4, decode: decNumber },
     '4': { name: 'protocol', len: 1, decode: decNumber },
     '5': { name: 'src_tos', len: 1, decode: decNumber },
     '6': { name: 'tcp_flags', len: 1, decode: decNumber },
     '7': { name: 'l4_src_port', len: 2, decode: decNumber },
     '8': { name: 'ipv4_src_addr', len: 4, decode: function(buf,len) {
         var ip = buf.readUInt32BE(0);
         return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
     }},
     '9': { name: 'src_mask', len: 1, decode: decNumber },
    '10': { name: 'input_snmp', len: 2, decode: decNumber },
    '11': { name: 'l4_dst_port', len: 2, decode: decNumber },
    '12': { name: 'ipv4_dst_addr', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '13': { name: 'dst_mask', len: 1, decode: decNumber },
    '14': { name: 'output_snmp', len: 2, decode: decNumber },
    '15': { name: 'ipv4_next_hop', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '16': { name: 'src_as', len: 2, decode: decNumber },
    '17': { name: 'dst_as', len: 2, decode: decNumber },
    '18': { name: 'bgp_ipv4_next_hop', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '19': { name: 'mul_dst_pkts', len: 4, decode: decNumber },
    '20': { name: 'mul_dst_bytes', len: 4, decode: decNumber },
    '21': { name: 'last_switched', len: 4, decode: decNumber },
    '22': { name: 'first_switched', len: 4, decode: decNumber },
    '23': { name: 'out_bytes', len: 4, decode: decNumber },
    '24': { name: 'out_pkts', len: 4, decode: decNumber },
    '25': { name: 'min_pkt_lngth', len: 2, decode: decNumber },
    '26': { name: 'max_pkt_lngth', len: 2, decode: decNumber },
    '27': { name: 'ipv6_src_addr', len: 16, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '28': { name: 'ipv6_dst_addr', len: 16, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '29': { name: 'ipv6_src_mask', len: 1, decode: decNumber },
    '30': { name: 'ipv6_dst_mask', len: 1, decode: decNumber },
    '31': { name: 'ipv6_flow_label', len: 3, decode: decNumber },
    '32': { name: 'icmp_type', len: 2, decode: decNumber },
    '33': { name: 'mul_igmp_type', len: 1, decode: decNumber },
    '34': { name: 'sampling_interval', len: 4, decode: decNumber },
    '35': { name: 'sampling_algorithm', len: 1, decode: decNumber },
    '36': { name: 'flow_active_timeout', len: 2, decode: decNumber },
    '37': { name: 'flow_inactive_timeout', len: 2, decode: decNumber },
    '38': { name: 'engine_type', len: 1, decode: decNumber },
    '39': { name: 'engine_id', len: 1, decode: decNumber },
    '40': { name: 'total_bytes_exp', len: 4, decode: decNumber },
    '41': { name: 'total_pkts_exp', len: 4, decode: decNumber },
    '42': { name: 'total_flows_exp', len: 4, decode: decNumber },
    '44': { name: 'ipv4_src_prefix', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '45': { name: 'ipv4_dst_prefix', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '46': { name: 'mpls_top_label_type', len: 1, decode: decNumber },
    '47': { name: 'mpls_top_label_ip_addr', len: 4, decode: function(buf,len) {
        var ip = buf.readUInt32BE(0);
        return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
    }},
    '48': { name: 'flow_sampler_id', len: 1, decode: decNumber },
    '49': { name: 'flow_sampler_mode', len: 1, decode: decNumber },
    '50': { name: 'flow_sampler_random_interval', len: 4, decode: decNumber },
    '52': { name: 'min_ttl', len: 1, decode: decNumber },
    '53': { name: 'max_ttl', len: 1, decode: decNumber },
    '54': { name: 'ipv4_ident', len: 2, decode: decNumber },
    '55': { name: 'dst_tos', len: 1, decode: decNumber },
    '56': { name: 'in_src_mac', len: 6, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '57': { name: 'out_dst_mac', len: 6, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '58': { name: 'src_vlan', len: 2, decode: decNumber },
    '59': { name: 'dst_vlan', len: 2, decode: decNumber },
    '60': { name: 'ip_protocol_version', len: 1, decode: decNumber },
    '61': { name: 'direction', len: 1, decode: decNumber },
    '62': { name: 'ipv6_next_hop', len: 16, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '63': { name: 'bpg_ipv6_next_hop', len: 16, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '64': { name: 'ipv6_option_headers', len: 4, decode: decNumber },
    '70': { name: 'mpls_label_1', len: 3, decode: decNumber },
    '71': { name: 'mpls_label_2', len: 3, decode: decNumber },
    '72': { name: 'mpls_label_3', len: 3, decode: decNumber },
    '73': { name: 'mpls_label_4', len: 3, decode: decNumber },
    '74': { name: 'mpls_label_5', len: 3, decode: decNumber },
    '75': { name: 'mpls_label_6', len: 3, decode: decNumber },
    '76': { name: 'mpls_label_7', len: 3, decode: decNumber },
    '77': { name: 'mpls_label_8', len: 3, decode: decNumber },
    '78': { name: 'mpls_label_9', len: 3, decode: decNumber },
    '79': { name: 'mpls_label_10', len: 3, decode: decNumber },
    '80': { name: 'in_dst_mac', len: 6, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '81': { name: 'out_src_mac', len: 6, decode: function(buf,len) {
        return buf.toString('hex',0,len);
    }},
    '82': { name: 'if_name', len: 2, decode: function(buf,len) {
        return buf.toString('utf8',0,len);
    }},
    '83': { name: 'if_desc', len: 4, decode: function(buf,len) {
        return buf.toString('utf8',0,len);
    }},
    '84': { name: 'sampler_name', len: 4, decode: function(buf,len) {
        return buf.toString('utf8',0,len);
    }},
    '85': { name: 'in_permanent_bytes', len: 4, decode: decNumber },
    '86': { name: 'in_permanent_pkts', len: 4, decode: decNumber },
    '88': { name: 'fragment_offset', len: 2, decode: decNumber },
    '89': { name: 'fw_status', len: 1, decode: decNumber },
    '90': { name: 'mpls_pal_rd', len: 8, decode: function(buf,len) {
        return decNumber(buf,len);
    }},
    '91': { name: 'mpls_prefix_len', len: 1, decode: decNumber },
    '92': { name: 'src_traffic_index', len: 4, decode: decNumber },
    '93': { name: 'dst_traffic_index', len: 4, decode: decNumber },
    '94': { name: 'application_descr', len: 4, decode: function(buf,len) {
        return buf.toString('utf8',0,len);
    }},
    '95': { name: 'application_tag', len: 4, decode: function(buf,len) {
        return buf.slice(0,len);
    }},
    '96': { name: 'application_name', len: 4, decode: function(buf,len) {
        return buf.toString('utf8',0,len);
    }},
    '98': { name: 'DiffServCodePoint', len: 1, decode: decNumber },
    '99': { name: 'replication_factor', len: 4, decode: decNumber },
    '128': { name: 'in_as', len: 4, decode: decNumber },
    '129': { name: 'out_as', len: 4, decode: decNumber }
};

function NetFlowV9(cb) {
    if (!(this instanceof NetFlowV9)) return new NetFlowV9(cb);

    var me = this;
    this.templates = {};

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        var len  = buffer.readUInt16BE(2);
        var buf = buffer.slice(4,len);
        while(buf.length>0) {
            var tId  = buf.readUInt16BE(0);
            var cnt  = buf.readUInt16BE(2);
            var list = [];
            //console.log('B',buffer.length,buf.length,tId,cnt);
            for (var i = 0; i<cnt; i++) {
                list.push({ type: buf.readUInt16BE(4+4*i), len: buf.readUInt16BE(6+4*i) });
            }
            me.templates[tId] = list;
            buf = buf.slice(4+cnt*4);
        }
    }

    function decodeTemplate(buf) {
        var fsId = buf.readUInt16BE(0);
        // var len = buf.readUInt16BE(2);
        var t = me.templates[fsId];
        var n = 4;
        var o = {};
        var z;
        var nf;
        for (var i=0;i< t.length;i++) {
            z=t[i];
            nf = nfTypes[z.type];
            if (nf) 
                o[nf.name] = nf.decode(buf.slice(n), z.len);
            else
                console.log('Unknown NF Type', z);
            n+= z.len;
        }
        return o;
    }

    this.server = dgram.createSocket('udp4');
    this.server.on('message',function(msg, rinfo) {
        //console.log('rinfo',rinfo);
        if (rinfo.size<20) return;
        var header = {};
        var o = {};
        header.version = msg.readUInt16BE(0);
        header.count = msg.readUInt16BE(2);
        header.uptime = msg.readUInt32BE(4);
        header.seconds = msg.readUInt32BE(8);
        header.sequence = msg.readUInt32BE(12);
        header.sourceId = msg.readUInt32BE(16);
        if (header.version!=9) return;

        var buf = msg.slice(20);
        while(buf.length>0) {
            var fsId = buf.readUInt16BE(0);
            var len = buf.readUInt16BE(2);
            // ----
            if (fsId==0) readTemplate(buf);

            if (typeof me.templates[fsId] != 'undefined') {
                // Now we have to read the flowset
                o = decodeTemplate(buf);
                if (cb) cb({
                    header: header,
                    rinfo: rinfo,
                    flow: o
                });
            }
            // ----
            buf = buf.slice(len);
        }
    });
    this.listen = function(port) {
        var me = this;
        setTimeout(function() {
            me.server.bind(port);
        },50);
    };
}

module.exports = NetFlowV9;
