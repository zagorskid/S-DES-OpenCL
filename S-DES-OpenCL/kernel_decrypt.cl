// constant variables
const short int sBlock0[16] = {
	1, 0, 3, 2,
	3, 2, 1, 0,
	0, 2, 1, 3,
	3, 1, 3, 2
};
const short int sBlock1[16] = {
	0, 1, 2, 3,
	2, 0, 1, 3,
	3, 0, 1, 0,
	2, 1, 0, 3
};


// functions
inline short int binToDec(short int bin1, short int bin2);
inline short int binToDec(short int bin1, short int bin2)
{
	if (bin1 == 0 && bin2 == 1)
	{
		return 1;
	}
	else if (bin1 == 1 && bin2 == 0)
	{
		return 2;
	}
	else if (bin1 == 1 && bin2 == 1)
	{
		return 3;
	}
	else // bin1 == 0 && bin2 == 0
	{
		return 0;
	}
}



__kernel void decrypt(__global const unsigned char* inputText, __global const short int* subKeyK1, __global const short int* subKeyK2,
	__global unsigned char* outputText, unsigned long int fileLength, unsigned long int numberOfThreads)
{

	unsigned long int id = get_global_id(0);
	short int inputBlock[8] = { 0 }; // blockSize = 8

	for (unsigned long int n = id; n < fileLength; n += numberOfThreads)
	{
		unsigned char plainChar = inputText[n];

		// conversion from char to binary
		for (int i = 7; i >= 0; --i)
		{
			inputBlock[7 - i] = (short int)((plainChar & (1 << i)) ? 1 : 0);
		}

		// permutation IP of inputBlock
		// IP = [ 1 5 2 0 3 7 4 6 ] 
		short int tmp[8];
		for (int i = 0; i < 8; ++i)
		{
			tmp[i] = inputBlock[i];
		}

		inputBlock[0] = tmp[1];
		inputBlock[1] = tmp[5];
		inputBlock[2] = tmp[2];
		inputBlock[3] = tmp[0];
		inputBlock[4] = tmp[3];
		inputBlock[5] = tmp[7];
		inputBlock[6] = tmp[4];
		inputBlock[7] = tmp[6];


		// FunctionF with subKeyK2	
		// split input block L / R
		short int blockLeft[4] = { inputBlock[0], inputBlock[1], inputBlock[2], inputBlock[3] };
		short int blockRight[4] = { inputBlock[4], inputBlock[5], inputBlock[6], inputBlock[7] };

		// 4 -> 8-bit block extension (Extending Permutation E)
		short int blockExt[8] = { blockRight[3], blockRight[0], blockRight[1], blockRight[2], blockRight[1], blockRight[2], blockRight[3], blockRight[0] };

		// blockExt XOR subKey
		for (int i = 0; i < 8; ++i)
		{
			blockExt[i] = blockExt[i] ^ subKeyK2[i];
		}

		// S-Block S0 transformation
		short int numS0 = sBlock0[binToDec(blockExt[0], blockExt[3]) * 4 + binToDec(blockExt[1], blockExt[2])]; // row * widh + column
		short int numS1 = sBlock1[binToDec(blockExt[4], blockExt[7]) * 4 + binToDec(blockExt[5], blockExt[6])]; // row * widh + column

		// block P4 -> stored in tmpBlock array
		short int tmpBlock[4] = { 0 };
		// P4 permutation: [ 1 3 2 0 ]
		// L-part:
		if (numS0 == 0)
		{
			tmpBlock[3] = 0; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 0; // tmpBlock[1] before permutation P4
		}
		else if (numS0 == 1)
		{
			tmpBlock[3] = 0; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 1; // tmpBlock[1] before permutation P4
		}
		else if (numS0 == 2)
		{
			tmpBlock[3] = 1; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 0; // tmpBlock[1] before permutation P4
		}
		else
		{
			tmpBlock[3] = 1; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 1; // tmpBlock[1] before permutation P4
		}

		// R-part:
		if (numS1 == 0)
		{
			tmpBlock[2] = 0; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 0; // tmpBlock[3] before permutation P4
		}
		else if (numS1 == 1)
		{
			tmpBlock[2] = 0; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 1; // tmpBlock[3] before permutation P4
		}
		else if (numS1 == 2)
		{
			tmpBlock[2] = 1; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 0; // tmpBlock[3] before permutation P4
		}
		else
		{
			tmpBlock[2] = 1; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 1; // tmpBlock[3] before permutation P4
		}

		// blockLeft XOR block P4 (stored in tmpBlock)
		for (int i = 0; i < 4; ++i)
		{
			inputBlock[i] = blockLeft[i] ^ tmpBlock[i];
		}

		// final block -> stored in block array
		// block[0] : block[3] -> blockLeft XOR block P4
		// block[4] : block[7] -> blockRight
		inputBlock[4] = blockRight[0];
		inputBlock[5] = blockRight[1];
		inputBlock[6] = blockRight[2];
		inputBlock[7] = blockRight[3];


		// SW
		// input =	[ 0 1 2 3 4 5 6 7 ]
		// output = [ 4 5 6 7 0 1 2 3 ]		
		short int tmp_val = inputBlock[0];
		inputBlock[0] = inputBlock[4];
		inputBlock[4] = tmp_val;
		tmp_val = inputBlock[1];
		inputBlock[1] = inputBlock[5];
		inputBlock[5] = tmp_val;
		tmp_val = inputBlock[2];
		inputBlock[2] = inputBlock[6];
		inputBlock[6] = tmp_val;
		tmp_val = inputBlock[3];
		inputBlock[3] = inputBlock[7];
		inputBlock[7] = tmp_val;


		// FunctionF with subKeyK1
		// split input block L / R
		blockLeft[0] = inputBlock[0];
		blockLeft[1] = inputBlock[1];
		blockLeft[2] = inputBlock[2];
		blockLeft[3] = inputBlock[3];

		blockRight[0] = inputBlock[4];
		blockRight[1] = inputBlock[5];
		blockRight[2] = inputBlock[6];
		blockRight[3] = inputBlock[7];

		// 4 -> 8-bit block extension (Extending Permutation E)
		blockExt[0] = blockRight[3];
		blockExt[1] = blockRight[0];
		blockExt[2] = blockRight[1];
		blockExt[3] = blockRight[2];
		blockExt[4] = blockRight[1];
		blockExt[5] = blockRight[2];
		blockExt[6] = blockRight[3];
		blockExt[7] = blockRight[0];

		// blockExt XOR subKey
		for (int i = 0; i < 8; ++i)
		{
			blockExt[i] = blockExt[i] ^ subKeyK1[i];
		}

		// S-Block S0 transformation
		numS0 = sBlock0[binToDec(blockExt[0], blockExt[3]) * 4 + binToDec(blockExt[1], blockExt[2])]; // row * widh + column
		numS1 = sBlock1[binToDec(blockExt[4], blockExt[7]) * 4 + binToDec(blockExt[5], blockExt[6])]; // row * widh + column

		// block P4 -> stored in tmpBlock array
		// P4 permutation: [ 1 3 2 0 ]
		// L-part:
		if (numS0 == 0)
		{
			tmpBlock[3] = 0; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 0; // tmpBlock[1] before permutation P4
		}
		else if (numS0 == 1)
		{
			tmpBlock[3] = 0; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 1; // tmpBlock[1] before permutation P4
		}
		else if (numS0 == 2)
		{
			tmpBlock[3] = 1; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 0; // tmpBlock[1] before permutation P4
		}
		else
		{
			tmpBlock[3] = 1; // tmpBlock[0] before permutation P4
			tmpBlock[0] = 1; // tmpBlock[1] before permutation P4
		}

		// R-part:
		if (numS1 == 0)
		{
			tmpBlock[2] = 0; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 0; // tmpBlock[3] before permutation P4
		}
		else if (numS1 == 1)
		{
			tmpBlock[2] = 0; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 1; // tmpBlock[3] before permutation P4
		}
		else if (numS1 == 2)
		{
			tmpBlock[2] = 1; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 0; // tmpBlock[3] before permutation P4
		}
		else
		{
			tmpBlock[2] = 1; // tmpBlock[2] before permutation P4
			tmpBlock[1] = 1; // tmpBlock[3] before permutation P4
		}

		// blockLeft XOR block P4 (stored in tmpBlock)
		for (int i = 0; i < 4; ++i)
		{
			inputBlock[i] = blockLeft[i] ^ tmpBlock[i];
		}

		// final block -> stored in block array
		// block[0] : block[3] -> blockLeft XOR block P4
		// block[4] : block[7] -> blockRight
		inputBlock[4] = blockRight[0];
		inputBlock[5] = blockRight[1];
		inputBlock[6] = blockRight[2];
		inputBlock[7] = blockRight[3];


		// permutation ReIP of inputBlock
		// IP^-1 = [ 4 1 3 5 7 2 8 6 ]
		// IP^-1 = [ 3 0 2 4 6 1 7 5 ] -> indexes starts from 0		
		for (int i = 0; i < 8; ++i)
		{
			tmp[i] = inputBlock[i];
		}

		inputBlock[0] = tmp[3];
		inputBlock[1] = tmp[0];
		inputBlock[2] = tmp[2];
		inputBlock[3] = tmp[4];
		inputBlock[4] = tmp[6];
		inputBlock[5] = tmp[1];
		inputBlock[6] = tmp[7];
		inputBlock[7] = tmp[5];


		// conversion from binary to char
		short int outputVal = 0;
		short int factor = 128;
		for (int i = 0; i < 8; ++i)
		{
			outputVal += (factor * inputBlock[i]);
			factor = factor >> 1;
		}

		//short int outputVal = 65;
		outputText[n] = (unsigned char)outputVal;
	}

}