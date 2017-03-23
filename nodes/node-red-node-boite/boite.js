/**
 * Copyright 2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 **/

module.exports = function(RED) {
    "use strict";
    var crypto = require("crypto");
    var fs = require("fs");
    var request = require("request");
    var url = require("url");
    var minimatch = require("minimatch");
    var Cloudant = require("cloudant");
    var cloudant = Cloudant({vcapServices: JSON.parse(process.env.VCAP_SERVICES)});
    var credDB = cloudant.use("test");
    var credDBrev = '';

    function BoiteNode(n) {
        RED.nodes.createNode(this,n);
    }
    RED.nodes.registerType("boite-credentials", BoiteNode, {
        credentials: {
            displayName: {type:"text"},
            clientId: {type:"text"},
            clientSecret: {type:"password"},
            accessToken: {type:"password"},
            refreshToken: {type:"password"},
            expireTime: {type:"password"},
            //
            //  SP+
            //  To better manage credentials
            //
            expiresIn: {type:"password"},
            refreshTime: {type:"password"}
            //
            //  SP-
            //
        }
    });

    //
    //  SP+
    //  Debugging functions
    //
    function _dumpCallback(err, result, data) {
         if (err) {
            console.log('======= ERR ==========');
            console.log(JSON.stringify(err, null, 2));
        }
        if (result) {
            console.log('======= result 2 ==========');
            console.log(result.statusCode);
            console.log(result.statusMessage);
            console.log(JSON.stringify(result.headers, null, 2));
        }
        if (data) {
            console.log('======= data 2 ==========');
            console.log(JSON.stringify(data, null, 2));
        }       
    }
    
    function _dumpCred(credentials, header) {
        console.log('******** ' + header + ' ************** ');
        console.log('Client Id : ' + credentials.clientId);
        console.log('Client Secret : ' + credentials.clientSecret);
        console.log('Access Token : ' + credentials.accessToken);
        console.log('Refresh Token : ' + credentials.refreshToken);
        console.log('Token Type : ' + credentials.tokenType);
        console.log('Expires In : ' + credentials.expiresIn);
        var xyz = new Date(credentials.expireTime*1000).toUTCString()
        console.log('Expire Time : ' + xyz);
        console.log('last refresh : ' + credentials.refreshTime);
        console.log('*********************************************');
    }
    //
    //  SP-
    //
    
    BoiteNode.prototype.refreshToken = function(cb) {
        var credentials = this.credentials;
        var node = this;
        //console.log("refreshing token: " + credentials.refreshToken);
        if (!credentials.refreshToken) {
            // TODO: add a timeout to make sure we make a request
            // every so often (if no flows trigger one) to ensure the
            // refresh token does not expire
            node.error(RED._("boite.error.no-refresh-token"));
            return cb(RED._("boite.error.no-refresh-token"));
        }
        //
        //  SP+
        //
        //  read RefreshToekn from the temporary storage to bypass the issue of credentials being saved ONLY on deploy
        //
        //
        _dumpCred(credentials, 'During Refresh');
        //var infos = fs.readFileSync('./public/' + node.id + '_cred.json').toString('utf8');
        //var infosJ = JSON.parse(infos);
        
        credDB.get(node.id, function(err, data){
            if (err) {
                node.error('Error Writing Credentials to storage :  ', err);                
            } else {
                var newRefresh = data.credentials.refreshToken;
                console.log('Refreshing using the following refresh token : ' + newRefresh);
                //
                //  SP-
                //
                request.post({
                    url: 'https://api.box.com/oauth2/token',
                    json: true,
                    form: {
                        grant_type: 'refresh_token',
                        client_id: credentials.clientId,
                        client_secret: credentials.clientSecret,
                        //
                        //  SP+
                        //  
                        //  Change from where the RefreshToken is taken
                        //
                        refresh_token: newRefresh,
                        //refresh_token: credentials.refreshToken,
                        //
                        //  SP-
                        //
                    },
                }, function(err, result, data) {
                    //  _dumpCallback(err, result, data);
                    if (err) {
                        node.error(RED._("boite.error.token-request-error",{err:err}));
                        return;
                    }
                    if (data.error) {
                        console.log(data.error);
                        node.error(RED._("boite.error.refresh-token-error",{message:data.error}));
                        return;
                    }
                    // console.log("refreshed: " + require('util').inspect(data));
                    credentials.accessToken = data.access_token;
                    if (data.refresh_token) {
                        credentials.refreshToken = data.refresh_token;
                    }
                    credentials.expiresIn = data.expires_in;
                    credentials.expireTime =
                        credentials.expiresIn + (new Date().getTime()/1000);
                    credentials.refreshTime = new Date().toUTCString();
                    credentials.tokenType = data.token_type;
                    RED.nodes.addCredentials(node.id, credentials);
                    _dumpCred(credentials, 'After Refresh');
                    
                    //fs.writeFileSync('./public/' + node.id + '_cred.json', JSON.stringify(credentials, null, 2));
                    //console.log('Updating file ' + node.id + '_cred.json !');
                    //
                    //  SP+
                    //
                    //  After adding Credentials, save Credentials to permanent store
                    //
                    var newRec = {credentials : credentials, _id : node.id};
                    if (credDBrev != '') {
                        newRec._rev = credDBrev;
                    }
                    credDB.insert(, function(err, body, header) {
                        if (err) {
                            node.error('Error Writing Credentials to storage :  ', err);
                        } else {
                            //
                            //  store REV
                            //
                            credDBrev = body._rev;
                            //
                            //  SP-
                            //
                            if (typeof cb !== undefined) {
                                cb();
                            }
                        }
                    });
                });
            }
        })
    };

    BoiteNode.prototype.request = function(req, retries, cb) {
        var node = this;
        if (typeof retries === 'function') {
            cb = retries;
            retries = 1;
        }
        if (typeof req !== 'object') {
            req = { url: req };
        }
        req.method = req.method || 'GET';
        if (!req.hasOwnProperty("json")) {
            req.json = true;
        }
        // always set access token to the latest ignoring any already present
        req.auth = { bearer: this.credentials.accessToken };
        /*
        //  SP+
        //
        //  We cannot trust in the expires_in value returned by BOX
        //  The risk is to generate new accessToken too frequently, instead than each 60 days.
        //  This would make the node UNSTABLE after the restart of Node-Red in case a prompt DEPLOY 
        //  has been done
        //  So, let's ONLY trust in 401
        //
        if (!this.credentials.expireTime ||
            this.credentials.expireTime < (new Date().getTime()/1000)) {
            if (retries === 0) {
                node.error(RED._("boite.error.too-many-refresh-attempts"));
                cb(RED._("boite.error.too-many-refresh-attempts"));
                return;
            }
            node.warn(RED._("boite.warn.refresh-token"));
            node.refreshToken(function (err) {
                if (err) {
                    return;
                }
                node.request(req, 0, cb);
            });
            return;
        }
        //
        //  SP-
        //
        */
        
        //
        //  SP+
        //
        _dumpCred(this.credentials, 'Making BOX2 request');
        //
        //  SP-
        //
        return request(req, function(err, result, data) {
            //  _dumpCallback(err, result, data);
            if (err) {
                // handled in callback
                return cb(err, data);
            }
            if (result.statusCode === 401 && retries > 0) {
                //
                //  SP+
                // 
                console.log('***** Getting a 401 ******** ');
                //
                //  SP-
                //
                retries--;
                node.warn(RED._("boite.warn.refresh-401"));
                node.refreshToken(function (err) {
                    if (err) {
                        return cb(err, null);
                    }
                    return node.request(req, retries, cb);
                });
            } else if (result.statusCode >= 400) {
                //
                //  SP+
                //
                //  Changed to "elseif" otherwise a 401 would be treated TWO TIMES
                //
                //
                console.log('REQUEST WITH status > 400... Invoking callback');
                //
                //  SP-
                //
                return cb(result.statusCode + ": " + data.message, data);
            } else {                
                return cb(err, data);
            }
        });
    };

    BoiteNode.prototype.folderInfo = function(parent_id, cb) {
        this.request('https://api.box.com/2.0/folders/'+parent_id, cb);
    };

    BoiteNode.prototype.resolvePath = function(path, parent_id, cb) {
        var node = this;
        if (typeof parent_id === 'function') {
            cb = parent_id;
            parent_id = 0;
        }
        if (typeof path === "string") {
            // split path and remove empty string components
           path = path.split("/").filter(function(e) { return e !== ""; });
           // TODO: could also handle '/blah/../' and '/./' perhaps
        } else {
           path = path.filter(function(e) { return e !== ""; });
        }
        if (path.length === 0) {
            return cb(null, parent_id);
        }
        var folder = path.shift();
        node.folderInfo(parent_id, function(err, data) {
            if (err) {
                return cb(err, -1);
            }
            var entries = data.item_collection.entries;
            for (var i = 0; i < entries.length; i++) {
                if (entries[i].type === 'folder' &&
                    entries[i].name === folder) {
                    // found
                    return node.resolvePath(path, entries[i].id, cb);
                }
            }
            return cb(RED._("boite.error.not-found"), -1);
        });
    };

    BoiteNode.prototype.resolveFile = function(path, parent_id, cb) {
        var node = this;
        if (typeof parent_id === 'function') {
            cb = parent_id;
            parent_id = 0;
        }
        if (typeof path === "string") {
            // split path and remove empty string components
           path = path.split("/").filter(function(e) { return e !== ""; });
            // TODO: could also handle '/blah/../' and '/./' perhaps
        } else {
            path = path.filter(function(e) { return e !== ""; });
        }
        if (path.length === 0) {
            return cb(RED._("boite.error.missing-filename"), -1);
        }
        var file = path.pop();
        node.resolvePath(path, function(err, parent_id) {
            if (err) {
                return cb(err, parent_id);
            }
            node.folderInfo(parent_id, function(err, data) {
                if (err) {
                    return cb(err, -1);
                }
                var entries = data.item_collection.entries;
                for (var i = 0; i < entries.length; i++) {
                    if (entries[i].type === 'file' &&
                        entries[i].name === file) {
                        // found
                        return cb(null, entries[i].id);
                    }
                }
                return cb(RED._("boite.error.not-found"), -1);
            });
        });
    };

    function constructFullPath(entry) {
        var parentPath = entry.path_collection.entries
            .filter(function (e) { return e.id !== "0"; })
            .map(function (e) { return e.name; })
            .join('/');
        return (parentPath !== "" ? parentPath+'/' : "") + entry.name;
    }

    RED.httpAdmin.get('/boite-credentials/auth', function(req, res){
        if (!req.query.clientId || !req.query.clientSecret ||
            !req.query.id || !req.query.callback) {
            res.send(400);
            return;
        }
        var node_id = req.query.id;
        var callback = req.query.callback;
        var credentials = {
            clientId: req.query.clientId,
            clientSecret: req.query.clientSecret
        };

        var csrfToken = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
        credentials.csrfToken = csrfToken;
        credentials.callback = callback;
        res.cookie('csrf', csrfToken);
        res.redirect(url.format({
            protocol: 'https',
            hostname: 'app.box.com',
            pathname: '/api/oauth2/authorize',
            query: {
                response_type: 'code',
                client_id: credentials.clientId,
                state: node_id + ":" + csrfToken,
                redirect_uri: callback
            }
        }));
        RED.nodes.addCredentials(node_id, credentials);
    });

    RED.httpAdmin.get('/boite-credentials/auth/callback', function(req, res) {
        if (req.query.error) {
            return res.send('ERROR: '+ req.query.error + ': ' + req.query.error_description);
        }
        var state = req.query.state.split(':');
        var node_id = state[0];
        var credentials = RED.nodes.getCredentials(node_id);
        if (!credentials || !credentials.clientId || !credentials.clientSecret) {
            return res.send(RED._("boite.error.no-credentials"));
        }
        if (state[1] !== credentials.csrfToken) {
            return res.status(401).send(
                RED._("boite.error.token-mismatch")
            );
        }

        request.post({
            url: 'https://app.box.com/api/oauth2/token',
            json: true,
            form: {
                grant_type: 'authorization_code',
                code: req.query.code,
                client_id: credentials.clientId,
                client_secret: credentials.clientSecret,
                redirect_uri: credentials.callback,
            },
        }, function(err, result, data) {
            if (err) {
                console.log("request error:" + err);
                return res.send(RED._("boite.error.something-broke"));
            }
            if (data.error) {
                console.log("oauth error: " + data.error);
                return res.send(RED._("boite.error.something-broke"));
            }
            //console.log("data: " + require('util').inspect(data));
            credentials.accessToken = data.access_token;
            credentials.refreshToken = data.refresh_token;
            credentials.expiresIn = data.expires_in;
            credentials.expireTime =
                credentials.expiresIn + (new Date().getTime()/1000);
            credentials.refreshTime = new Date().toUTCString();
            credentials.tokenType = data.token_type;
            delete credentials.csrfToken;
            delete credentials.callback;
            RED.nodes.addCredentials(node_id, credentials);
            //
            //  SP+
            //  
            //  Writing credentials in persistent store
            //
            _dumpCred(credentials, 'First Authorization');
            //fs.writeFileSync('./public/' + node_id + '_cred.json', JSON.stringify(credentials, null, 2));
            console.log('Refreshing file record ' + node_id);
            var newRec = {credentials : credentials, _id : node_id};
            if (credDBrev != '') {
                newRec._rev = credDBrev;
            }
            credDB.insert(newRec, function(err, body, header) {
                if (err) {
                    node.error('Error Writing Credentials to storage :  ', err);
                } else {
                    //
                    //  store REV
                    //
                    credDBrev = body._rev;
                    //
                    //  SP-
                    //
                    request.get({
                        url: 'https://api.box.com/2.0/users/me',
                        json: true,
                        auth: { bearer: credentials.accessToken },
                    }, function(err, result, data) {
                        if (err) {
                            console.log('fetching box profile failed: ' + err);
                            return res.send(RED._("boite.error.profile-fetch-failed"));
                        }
                        if (result.statusCode >= 400) {
                            console.log('fetching box profile failed: ' +
                                        result.statusCode + ": " + data.message);
                            return res.send(RED._("boite.error.profile-fetch-failed"));
                        }
                        if (!data.name) {
                            console.log('fetching box profile failed: no name found');
                            return res.send(RED._("boite.error.profile-fetch-failed"));
                        }
                        credentials.displayName = data.name;
                        RED.nodes.addCredentials(node_id, credentials);
                        res.send(RED._("boite.error.authorized"));
                    });
                }
            });
        });
    });

    function BoiteInNode(n) {
        RED.nodes.createNode(this,n);
        this.filepattern = n.filepattern || "";
        this.boite = RED.nodes.getNode(n.boite);
        var node = this;
        if (!this.boite || !this.boite.credentials.accessToken) {
            this.warn(RED._("boite.warn.missing-credentials"));
            return;
        }
        node.status({fill:"blue",shape:"dot",text:"boite.status.initializing"});
        this.boite.request({
            url: 'https://api.box.com/2.0/events?stream_position=now&stream_type=changes',
        }, function (err, data) {
            if (err) {
                node.error(RED._("boite.error.event-stream-initialize-failed",{err:err.toString()}));
                node.status({fill:"red",shape:"ring",text:"boite.status.failed"});
                return;
            }
            node.state = data.next_stream_position;
            node.status({});
            node.on("input", function(msg) {
                node.status({fill:"blue",shape:"dot",text:"boite.status.checking-for-events"});
                node.boite.request({
                    url: 'https://api.box.com/2.0/events?stream_position='+node.state+'&stream_type=changes',
                }, function(err, data) {
                    if (err) {
                        node.error(RED._("boite.error.events-fetch-failed",{err:err.toString()}),msg);
                        node.status({});
                        return;
                    }
                    node.status({});
                    node.state = data.next_stream_position;
                    for (var i = 0; i < data.entries.length; i++) {
                        // TODO: support other event types
                        // TODO: suppress duplicate events
                        // for both of the above see:
                        //    https://developers.box.com/docs/#events
                        var event;
                        if (data.entries[i].event_type === 'ITEM_CREATE') {
                            event = 'add';
                        } else if (data.entries[i].event_type === 'ITEM_UPLOAD') {
                            event = 'add';
                        } else if (data.entries[i].event_type === 'ITEM_RENAME') {
                            event = 'add';
                            // TODO: emit delete event?
                        } else if (data.entries[i].event_type === 'ITEM_TRASH') {
                            // need to find old path
                            node.lookupOldPath({}, data.entries[i], 'delete');
                            /* strictly speaking the {} argument above should
                             * be clone(msg) but:
                             *   - it must be {}
                             *   - if there was any possibility of a different
                             *     msg then it should be cloned using the
                             *     node-red/red/nodes/Node.js cloning function
                             */
                            continue;
                        } else {
                            event = 'unknown';
                        }
                        //console.log(JSON.stringify(data.entries[i], null, 2));
                        node.sendEvent(msg, data.entries[i], event);
                    }
                });
            });
            var interval = setInterval(function() {
                node.emit("input", {});
            }, 900000); // 15 minutes
            node.on("close", function() {
                if (interval !== null) {
                    clearInterval(interval);
                }
            });
        });
    }
    RED.nodes.registerType("boite in", BoiteInNode);

    BoiteInNode.prototype.sendEvent = function(msg, entry, event, path) {
        var source = entry.source;
        if (typeof path === "undefined") {
            path = constructFullPath(source);
        }
        if (this.filepattern && !minimatch(path, this.filepattern)) {
            return;
        }
        msg.file = source.name;
        msg.payload = path;
        msg.event = event;
        msg.data = entry;
        this.send(msg);
    };

    BoiteInNode.prototype.lookupOldPath = function (msg, entry, event) {
        var source = entry.source;
        this.status({fill:"blue",shape:"dot",text:"boite.status.resolving-path"});
        var node = this;
        node.boite.folderInfo(source.parent.id, function(err, folder) {
            if (err) {
                node.warn(RED._("boite.warn.old-path-failed",{err:err.toString()}));
                node.status({fill:"red",shape:"ring",text:"boite.status.failed"});
                return;
            }
            node.status({});
            // TODO: add folder path_collection to entry.parent?
            var parentPath = constructFullPath(folder);
            node.sendEvent(msg, entry, event,
                (parentPath !== "" ? parentPath + '/' : '') + source.name);
        });
    };

    function BoiteQueryNode(n) {
        RED.nodes.createNode(this,n);
        this.filename = n.filename || "";
        this.boite = RED.nodes.getNode(n.boite);

        var node = this;
        if (!this.boite || !this.boite.credentials.accessToken) {
            this.warn(RED._("boite.warn.missing-credentials"));
            return;
        }

        node.on("input", function(msg) {
            var filename = node.filename || msg.filename;
            if (filename === "") {
                node.error(RED._("boite.error.no-filename-specified"));
                return;
            }
            msg.filename = filename;
            node.status({fill:"blue",shape:"dot",text:"boite.status.resolving-path"});
            switch (n.action) {
                case "GetInfo" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        var fields = "?fields=";
                        fields += "version_number,comment_count,permissions,tags,lock,extension,is_package,watermark_info";
                        node.status({fill: "blue", shape: "dot", text: "boite.status.gettingInfo"});
                        node.boite.request({
                            url: 'https://api.box.com/2.0/files/' + file_id + fields,
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.info-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
                case "UpdateInfo" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        var infoContent = '';
                        if ((n.infoContent == '') && ((msg.infoContent == undefined) || (msg.infoContent == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing value for the UpdateInfo');
                            node.status({fill:"red",shape:"dot",text:"Missing value for UpdateInfo"});
                            node.error('Missing value for UpdateInfo', msg);
                            return;
                        } else {
                            if (n.infoContent != '') {
                                infoContent = n.infoContent;
                            } else {
                                infoContent = msg.infoContent;
                            }
                        }
                        node.status({fill: "blue", shape: "dot", text: "boite.status.updatingInfo"});
                        node.boite.request({
                            method: 'PUT',
                            url: 'https://api.box.com/2.0/files/' + file_id,
                            body : infoContent,
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.link-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
                case "CreateLink" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        node.status({fill: "blue", shape: "dot", text: "boite.status.gettingLink"});
                        node.boite.request({
                            method: 'PUT',
                            url: 'https://api.box.com/2.0/files/' + file_id,
                            body : '{"shared_link": {}}',
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.link-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
                case "GetMetadata" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        //
                        //  Retrieve name for Metadata to be set
                        //
                        var metadataName = '';
                        if ((n.metadataName == '') && ((msg.metadataName == undefined) || (msg.metadataName == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing metadataName');
                            node.status({fill:"red",shape:"dot",text:"Missing metadataName"});
                            node.error('Missing metadataName', msg);
                            return;
                        } else {
                            if (n.metadataName != '') {
                                metadataName = n.metadataName;
                            } else {
                                metadataName = msg.metadataName;
                            }
                        }
                        //
                        //  Build the URL
                        //
                        var URL = 'https://api.box.com/2.0/files/' + file_id + '/metadata';
                        URL += '/enterprise/' + metadataName;
                        node.status({fill: "blue", shape: "dot", text: "boite.status.gettingMeta"});
                        node.boite.request({
                            method: 'GET',
                            url: URL,
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.meta-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                                msg.payload = '';
                                msg.error = err;
                                node.send(msg);
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
                case "SetMetadata" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        //
                        //  Retrieve content for Metadata to be set
                        //
                        var metadataContent = '';
                        if ((n.metadataContent == '') && ((msg.metadataContent == undefined) || (msg.metadataContent == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing value for the SetMetadata');
                            node.status({fill:"red",shape:"dot",text:"Missing value for SetMetadata"});
                            node.error('Missing value for SetMetadata', msg);
                            return;
                        } else {
                            if (n.metadataContent != '') {
                                metadataContent = n.metadataContent;
                            } else {
                                metadataContent = msg.metadataContent;
                            }
                        }
                        //
                        //  Retrieve name for Metadata to be set
                        //
                        var metadataName = '';
                        if ((n.metadataName == '') && ((msg.metadataName == undefined) || (msg.metadataName == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing metadataName');
                            node.status({fill:"red",shape:"dot",text:"Missing metadataName"});
                            node.error('Missing metadataName', msg);
                            return;
                        } else {
                            if (n.metadataName != '') {
                                metadataName = n.metadataName;
                            } else {
                                metadataName = msg.metadataName;
                            }
                        }
                        //
                        //  Build the URL
                        //
                        var URL = 'https://api.box.com/2.0/files/' + file_id + '/metadata';
                        URL += '/enterprise/' + metadataName;
                        node.status({fill: "blue", shape: "dot", text: "boite.status.creatingMeta"});
                        node.boite.request({
                            method: 'POST',
                            body: metadataContent,
                            url: URL,
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.meta-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
                case "UpdateMetadata" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        //
                        //  Retrieve content for Metadata to be set
                        //
                        var metadataContent = '';
                        if ((n.metadataContent == '') && ((msg.metadataContent == undefined) || (msg.metadataContent == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing value for the SetMetadata');
                            node.status({fill:"red",shape:"dot",text:"Missing value for SetMetadata"});
                            node.error('Missing value for SetMetadata', msg);
                            return;
                        } else {
                            if (n.metadataContent != '') {
                                metadataContent = n.metadataContent;
                            } else {
                                metadataContent = msg.metadataContent;
                            }
                        }
                        //
                        //  Retrieve name for Metadata to be set
                        //
                        var metadataName = '';
                        if ((n.metadataName == '') && ((msg.metadataName == undefined) || (msg.metadataName == ''))) {
                            //
                            //  There is an issue
                            //
                            console.log('Missing metadataName');
                            node.status({fill:"red",shape:"dot",text:"Missing metadataName"});
                            node.error('Missing metadataName', msg);
                            return;
                        } else {
                            if (n.metadataName != '') {
                                metadataName = n.metadataName;
                            } else {
                                metadataName = msg.metadataName;
                            }
                        }
                        //
                        //  Build the URL
                        //
                        var URL = 'https://api.box.com/2.0/files/' + file_id + '/metadata';
                        URL += '/enterprise/' + metadataName;
                        node.status({fill: "blue", shape: "dot", text: "boite.status.updatingMeta"});
                        node.boite.request({
                            method: 'PUT',
                            body: metadataContent,
                            headers: {
                                'Content-Type' : 'application/json-patch+json'                            
                            },
                            url: URL,
                            json: true,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.meta-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                case "Download" :
                    node.boite.resolveFile(filename, function(err, file_id) {
                        if (err) {
                            node.error(RED._("boite.error.path-resolve-failed", {err: err.toString()}), msg);
                            node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            return;
                        }
                        node.status({fill: "blue", shape: "dot", text: "boite.status.downloading"});
                        node.boite.request({
                            url: 'https://api.box.com/2.0/files/' + file_id + '/content',
                            json: false,
                            followRedirect: true,
                            maxRedirects: 1,
                            encoding: null,
                        }, function(err, data) {
                            if (err) {
                                node.error(RED._("boite.error.download-failed", {err: err.toString()}), msg);
                                node.status({fill: "red", shape: "ring", text: "boite.status.failed"});
                            } else {
                                msg.payload = data;
                                delete msg.error;
                                node.status({});
                                node.send(msg);
                            }
                        });
                    });
                    break;
            }
        });
    }
    RED.nodes.registerType("boite", BoiteQueryNode);

    function BoiteOutNode(n) {
        RED.nodes.createNode(this,n);
        this.filename = n.filename || "";
        this.localFilename = n.localFilename || "";
        this.boite = RED.nodes.getNode(n.boite);
        var node = this;
        if (!this.boite || !this.boite.credentials.accessToken) {
            this.warn(RED._("boite.warn.missing-credentials"));
            return;
        }

        node.on("input", function(msg) {
            var filename = node.filename || msg.filename;
            if (filename === "") {
                node.error(RED._("boite.error.no-filename-specified"));
                return;
            }
            var path = filename.split("/");
            var basename = path.pop();
            node.status({fill:"blue",shape:"dot",text:"boite.status.resolving-path"});
            var localFilename = node.localFilename || msg.localFilename;
            if (!localFilename && typeof msg.payload === "undefined") {
                return;
            }
            node.boite.resolvePath(path, function(err, parent_id) {
                if (err) {
                    node.error(RED._("boite.error.path-resolve-failed",{err:err.toString()}),msg);
                    node.status({fill:"red",shape:"ring",text:"boite.status.failed"});
                    return;
                }
                node.status({fill:"blue",shape:"dot",text:"boite.status.uploading"});
                var r = node.boite.request({
                    method: 'POST',
                    url: 'https://upload.box.com/api/2.0/files/content',
                }, function(err, data) {
                    if (err) {
                        if (data && data.status === 409 &&
                            data.context_info && data.context_info.conflicts) {
                            // existing file, attempt to overwrite it
                            node.status({fill:"blue",shape:"dot",text:"boite.status.overwriting"});
                            var r = node.boite.request({
                                method: 'POST',
                                url: 'https://upload.box.com/api/2.0/files/'+
                                    data.context_info.conflicts.id+'/content',
                            }, function(err, data) {
                                if (err) {
                                    node.error(RED._("boite.error.upload-failed",{err:err.toString()}),msg);
                                    node.status({fill:"red",shape:"ring",text:"boite.status.failed"});
                                    return;
                                }
                                node.status({});
                            });
                            var form = r.form();
                            if (localFilename) {
                                form.append('filename', fs.createReadStream(localFilename),
                                            { filename: basename });
                            } else {
                                form.append('filename', RED.util.ensureBuffer(msg.payload),
                                { filename: basename });
                            }
                        } else {
                            node.error(RED._("boite.error.upload-failed",{err:err.toString()}),msg);
                            node.status({fill:"red",shape:"ring",text:"boite.status.failed"});
                        }
                        return;
                	}
					console.log(data);
                    //
                    //  SP+
                    //
                    //  Payload needs  to be returned as payload, not as entire message
                    //
                    msg.payload = data;
					node.send(msg);
                    //
                    //  SP-
                    //
                    node.status({});
                });
                var form = r.form();
                if (localFilename) {
                    form.append('filename', fs.createReadStream(localFilename),
                                { filename: basename });
                } else {
                    form.append('filename', RED.util.ensureBuffer(msg.payload),
                                { filename: basename });
                }
                form.append('parent_id', parent_id);
            });
        });
    }
    RED.nodes.registerType("boite out",BoiteOutNode);
};
