/*
Copyright 2016 Silent Circle, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

mergeInto(LibraryManager.library, {
  httpRequest: function(url, method, data, pcode) {
    var request = Module.syncRequest;
    var url = Pointer_stringify(url);
    var method = Pointer_stringify(method);
    var data = Pointer_stringify(data);
    var res = request(method, url, {
      headers: { "content-type": "application/json" },
      body: data
    });
    setValue(pcode, res.statusCode, 'i32');
    var body = res.body.toString("UTF-8");
    var buffer = _malloc(body.length + 1);
    writeStringToMemory(body, buffer);
    return buffer;
  },
  makeReadNotificationJSON: function() {
    var json = JSON.stringify({
      cmd: "rr",
      rr_time: new Date().toISOString()
    });
    var buffer = _malloc(json.length + 1);
    writeStringToMemory(json, buffer);
    return buffer;
  },
  mountFilesystem: function() {
    if (ENVIRONMENT_IS_NODE) {
      FS.mkdir('/axolotl');
      FS.mount(NODEFS, { root: '.' }, '/axolotl');
    }
  }
});

