# S-DES-OpenCL 
Parallel S-DES encryption using OpenCL :neckbeard:.

Tested on ATI Raden HD5750. Speedup compare to CPU (AMD Phenom II X4 945) @ 3,3 GHz: 35,8x faster.

### Sample output (file 500 MB)
```
S-DES encryption of file: lipsum-500mb.txt.
File loaded in          0.788 s
File size:              525165036 bytes.
threadsGroupSize:       256
numberOfThreads:        525165056
Encryption time:        2.085 s
File saved in           1.317 s
Total time elapsed:     4.685 s
Press any key to continue . . .
```
