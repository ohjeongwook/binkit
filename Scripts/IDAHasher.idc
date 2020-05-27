#include <idc.idc>

static main()
{
    Wait();
    RunPlugin( "BinKit", 1 );
    SaveBinKitAnalysis("Test.db");
    Exit( 0 );
}
