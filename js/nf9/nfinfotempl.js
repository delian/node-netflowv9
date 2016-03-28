function nfInfoTemplates(rinfo) {
    if (typeof this.templates === 'undefined') {
        this.templates = {};
    }
    var templates = this.templates;
    var id = rinfo.address + ':' + rinfo.port;
    if (typeof templates[id] === 'undefined') {
        this.templates[id] = {};
    }
    return templates[id];
}

module.exports = nfInfoTemplates;
