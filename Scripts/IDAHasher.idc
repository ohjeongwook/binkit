#include <idc.idc>

static main()
{
    Wait();
    RunPlugin( "IDAHasher", 1 );
    SaveIDAHasherAnalysis("Test.db");
    Exit( 0 );
}
