#include <QApplication>

#include "MainWindow.hpp"
#include "Theme.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("Xaynx Reverse Lab");
    QApplication::setOrganizationName("Xaynx");
    QApplication::setApplicationVersion(XRL_VERSION);
    xrl::ui::applyTheme(app);

    xrl::ui::MainWindow window;
    window.show();
    if (argc > 1) window.loadFile(QString::fromLocal8Bit(argv[1]));  // opens (never executes) the given file
    return app.exec();
}

