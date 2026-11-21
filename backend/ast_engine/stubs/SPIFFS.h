// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <FS.h>
class SPIFFSFS : public fs::FS { public: bool begin(bool formatOnFail = false); };
extern SPIFFSFS SPIFFS;
