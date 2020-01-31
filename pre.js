function dropHandler(ev) {
  console.log('File(s) dropped');

  ev.preventDefault();

  if(ev.dataTransfer.files.length < 1) return;

  let file = ev.dataTransfer.files.item(0);
  console.log(`File name: ${file.name}, size: ${file.size}`);
  let reader = new FileReader();
  reader.onload = evt => {
    let buffer_size = evt.target.result.byteLength;
    let buffer_address = Module._malloc(buffer_size);

    Module.HEAPU8.set(new Uint8Array(evt.target.result), buffer_address);
    Module.readFile(buffer_address, buffer_size);
  }
  reader.readAsArrayBuffer(file);
}

function dragOverHandler(ev) {
  ev.preventDefault();
}

function call_wasm() {
}

var Module = {
  onRuntimeInitialized: function() {
    call_wasm()
  },
};
