##These tools only compile with Windows SDK

CaptureCryptGenRandom: 
It captures the current RNG state into a file. We need this file to compute previous RNG states.
PreviousCryptGenOutputs:
This will compute the previous outputs. With this info, we can regenerate the keys.
