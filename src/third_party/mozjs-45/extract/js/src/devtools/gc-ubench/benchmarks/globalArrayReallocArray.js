window.tests.set('globalArrayReallocArray', (function() {
var garbage = [];
var garbageIndex = 0;
return {
    description: "var foo = [[,,,], ....]",
    load: (N) => { garbage = new Array(N); },
    unload: () => { garbage = []; garbageIndex = 0; },
    makeGarbage: (N) => {
        var a = [];
        for (var i = 0; i < N; i++) {
            a[i] = N - i;
        }
        garbage[garbageIndex++] = a;
        if (garbageIndex == garbage.length)
            garbageIndex = 0;
    }
};
})());
