// Custom shim -- NOT copied from upstream MagnusBilling (see NOTICE.md).
//
// index.html's inline bootstrap script calls t('...') before the real i18n
// loader would normally be in place, and references window.t unconditionally.
// Without something defining it, that throws and the rest of the boot
// sequence never begins. This is an identity passthrough, good enough since
// we only ever render English strings.
window.t = function (s) {
    return s;
};
