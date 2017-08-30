// frida script
// still develping.

function zz_monitor_dyld_export_function() {
    var export_functions = [
        "_dyld_image_count",
        "_dyld_get_image_header",
        "_dyld_get_image_vmaddr_slide",
        "_dyld_get_image_name",
        "_dyld_register_func_for_add_image",
        "_dyld_register_func_for_remove_image"
    ];
    for (var i = 0; i < export_functions.length; i++) {
        console.log(Module.findExportByName("dyld", export_functions[i]));
        Interceptor.attach(Module.findExportByName("dyld", export_functions[i]), {
            onEnter: function(args) {
                console.log('Context information:');
                console.log('Context  : ' + JSON.stringify(this.context));
                console.log('Return   : ' + this.returnAddress);
                console.log('ThreadId : ' + this.threadId);
                console.log('Depth    : ' + this.depth);
                console.log('Errornr  : ' + this.err);
                console.log("dyld:" + Object.prototype.toString.call(this));
            },
            onLeave: function(retval) {}
        });
    }
    return export_functions;
}
