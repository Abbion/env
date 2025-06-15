const Main = imports.ui.main;
const St = imports.gi.St;

let reservedArea;

function init() {}

function enable() {
    reservedArea = new St.Widget({
        name: 'floatingPanelSpacer',
        reactive: false,
        visible: true,
        width: global.screen_width,
        height: 38,
        style_class: 'floating-panel-reserve'
    });

    reservedArea.set_position(0, 0);

    Main.layoutManager.addChrome(reservedArea, {
        affectsStruts: true
    });
}


function disable() {
    if (reservedArea) {
        Main.layoutManager.removeChrome(reservedArea);
        reservedArea.destroy();
        reservedArea = null;
    }
}
