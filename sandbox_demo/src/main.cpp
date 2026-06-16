// ============================================================
//  main.cpp
// ============================================================
#include <QApplication>
#include <QMessageBox>
#include "MainWindow.h"
#include "DriverManager.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("SandboxFlt Demo");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("SandboxDemo");

    // Warn if not elevated — driver operations need it
    if (!DriverManager::isElevated()) {
        QMessageBox::warning(
            nullptr,
            "Elevation Required",
            "SandboxFlt Demo should be run as Administrator.\n\n"
            "Without elevation:\n"
            "  • Driver install/load will fail\n"
            "  • Job Object assignment may fail\n"
            "  • Process launching will still work\n\n"
            "Re-launch with 'Run as Administrator' for full functionality.");
    }

    MainWindow w;
    w.show();
    return app.exec();
}
