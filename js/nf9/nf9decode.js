var debug = require('debug')('NetFlowV9');

var decMacRule = {
    0: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

function nf9PktDecode(msg,rinfo) {
    var templates = this.nfInfoTemplates(rinfo);
    var nfTypes = this.nfTypes || {};
    var nfScope = this.nfScope || {};

    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        sequence: msg.readUInt32BE(12),
        sourceId: msg.readUInt32BE(16)
    }, flows: [] };

    function appendTemplate(tId) {
        var id = rinfo.address + ':' + rinfo.port;
        out.templates = out.templates || {};
        out.templates[id] = out.templates[id] || {};
        out.templates[id][tId] = templates[tId];
    }

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
        var f = "var o = Object.create(null); var t;\n";
        for (i = 0, n = 0; i < list.length; i++, n += z.len) {
            z = list[i];
            nf = nfTypes[z.type];
            if (!nf) {
                debug('Unknown NF type %d', z.type);
                nf = nfTypes[z.type] = {
                    name: 'unknown_type_'+ z.type,
                    compileRule: decMacRule
                };
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
            debug('compile template %s for %s:%d', tId, rinfo.address, rinfo.port);
            templates[tId] = {len: len, list: list, compiled: compileTemplate(list)};
            appendTemplate(tId);
            buf = buf.slice(4 + cnt * 4);
        }
    }

    function decodeTemplate(fsId, buf) {
        if (typeof templates[fsId].compiled !== 'function') {
            templates[fsId].compiled = compileTemplate(templates[fsId].list);
        }
        var o = templates[fsId].compiled(buf, nfTypes);
        o.fsId = fsId;
        return o;
    }

    function compileScope(type,pos,len) {
        if (!nfScope[type]) {
            nfScope[type] = { name: 'unknown_scope_'+type, compileRule: decMacRule };
            debug('Unknown scope TYPE: %d POS: %d LEN: %d',type,pos,len);
        }

        var nf = nfScope[type];
        var cr = null;
        if (nf.compileRule) {
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
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d for %s:%d',len,tId,osLen,oLen,buff,rinfo.address,rinfo.port);
        var plen = 0;
        var cr = "var o={ isOption: true }; var t;\n";
        var type; var tlen;

        // Read the SCOPE
        var buf = buff.slice(0,osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    SCOPE type: %d (%s) len: %d, plen: %d', type,nfTypes[type] ? nfTypes[type].name : 'unknown',tlen,plen);
            if (type>0) cr+=compileScope(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type,nfTypes[type] ? nfTypes[type].name : 'unknown',tlen,plen);
            if (type>0) cr+=compileStatement(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }
        cr+="// option "+tId+"\n";
        cr+="return o;";
        debug('option template compiled to %s',cr);
        templates[tId] = { len: plen, compiled: new Function('buf','nfTypes',cr) };
        appendTemplate(tId);
    }

    var buf = msg.slice(20);
    while (buf.length > 3) { // length > 3 allows us to skip padding
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
            debug('Unknown template/option data with flowset id %d for %s:%d',fsId,rinfo.address,rinfo.port);
        }
        buf = buf.slice(len);
    }

    return out;
}

module.exports = nf9PktDecode;
