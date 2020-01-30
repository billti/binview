function dropHandler(ev) {
  console.log('File(s) dropped');

  // Prevent default behavior (Prevent file from being opened)
  ev.preventDefault();

  if(ev.dataTransfer.files.length < 1) return;

  let file = ev.dataTransfer.files.item(0);
  console.log(`File name: ${file.name}, size: ${file.size}`);
  let reader = new FileReader();
  reader.onload = evt => {
    /** ArrayBuffer */
    // let buffer = new DataView(evt.target.result);
    // FS.writeFile("/file.bin", buffer);
    // let getFileSize = Module.cwrap('getFileSize', 'number', ['string']);
    // getFileSize("/file.bin");
    let buffer_size = evt.target.result.byteLength;
    let buffer_address = Module._malloc(buffer_size);

    Module.HEAPU8.set(new Uint8Array(evt.target.result), buffer_address);
    let readFile = Module.cwrap('readFile', null, ['number', 'number']);
    readFile(buffer_address, buffer_size);
  }
  reader.readAsArrayBuffer(file);
}

function dragOverHandler(ev) {
  // Prevent default behavior (Prevent file from being opened)
  ev.preventDefault();
}

function call_wasm() {
  int_sqrt = Module.cwrap('int_sqrt', 'number', ['number'])
  console.log(`sqrt(12) = ${int_sqrt(12)}`);
}

var Module = {
  onRuntimeInitialized: function() {
    call_wasm()
  },
};

/*
Example of allocating memory and copying into it

var buf = Module._malloc(myTypedArray.length*myTypedArray.BYTES_PER_ELEMENT);
Module.HEAPU8.set(myTypedArray, buf);
Module.ccall('my_function', 'number', ['number'], [buf]);
Module._free(buf);
*/
