// G#include "ooo_cpu.h"
#include <cstdlib>
#include <time.h>
#include <bitset>

#define BIMODAL_CTR_MAX  3
#define BIMODAL_CTR_INIT 2
#define TAGPRED_CTR_MAX  7
#define TAGPRED_CTR_INIT 0
#define BIMODALLOG   14
#define NUMTAGTABLES 8
#define TAGPREDLOG 10

#define TAKEN true
#define NOT_TAKEN false

uint32_t SatIncrement(uint32_t input, uint32_t max) {
    return input + (input < max ? 1 : 0);
}


uint32_t SatDecrement(uint32_t input) {
    return input - (input > 0 ? 1 : 0);
}


// Each entry in the tag Pred Table
struct TagEntry {
    int32_t ctr;
    uint32_t tag;
    int32_t usefulBits;
};

// Folded History implementation ... from ghr (geometric length) -> compressed(target)
struct CompressedHist {
    /// Objective is to convert geomLengt of GHR into tagPredLog which is of length equal to the index of the corresponding bank
    // It can be also used for tag when the final length would be the Tag
    uint32_t geomLength;
    uint32_t targetLength;
    uint32_t compHist;

    void updateCompHist(bitset<131> ghr) {
        // easier way below... see PPM paper Figure 2
        // creating important masks
        int mask = (1 << targetLength) - 1;
        int mask1 = ghr[geomLength] << (geomLength % targetLength);
        int mask2 = (1 << targetLength);
        compHist = (compHist << 1) + ghr[0];
        compHist ^= ((compHist & mask2) >> targetLength);
        compHist ^= mask1;
        compHist &= mask;

    }
};


class TagePredictor {
    // The state is defined for Gshare, change for your design
private:
    bitset<131> GHR[2];           // global history register
    // 16 bit path history
    int PHR[2];
    // Bimodal
    uint32_t *bimodal;          // pattern history table
    uint32_t historyLength; // history length
    uint32_t numBimodalEntries; // entries in pht
    uint32_t bimodalLog;
    //Tagged Predictors
    TagEntry *tagPred[NUMTAGTABLES];
    uint32_t numTagPredEntries;
    uint32_t tagPredLog;
    uint32_t geometric[NUMTAGTABLES];
    //Compressed Buffers
    CompressedHist indexComp[2][NUMTAGTABLES];
    CompressedHist tagComp[2][2][NUMTAGTABLES];

    // Predictions need to be global ?? recheck
    bool primePred;
    bool altPred;
    int primeBank;
    int altBank;
    // index had to be made global else recalculate for update
    uint32_t indexTagPred[NUMTAGTABLES];
    uint32_t tag[NUMTAGTABLES];
    uint32_t clock;
    int clock_flip;
    int32_t altBetterCount;

    int seed = 0;

    bool predDir;
public:

    int MYRANDOM() {
        seed++;
        seed ^= PHR[0];
        seed = (seed >> 21) + (seed << 11);
        seed ^= PHR[1];
        seed = (seed >> 10) + (seed << 22);
        return (seed);
    };

    // The interface to the four functions below CAN NOT be changed

    TagePredictor(void) {
        /// First initiating Bimodal Table
        // Its a simple 2 bit counter table

        bimodalLog = BIMODALLOG;
        numBimodalEntries = (1 << bimodalLog);
        bimodal = new uint32_t[numBimodalEntries];

        for (uint32_t ii = 0; ii < numBimodalEntries; ii++) {
            bimodal[ii] = BIMODAL_CTR_INIT;
        }

        // Next to initiating the taggedPredictors
        tagPredLog = TAGPREDLOG;
        numTagPredEntries = (1 << tagPredLog);
        //cout << " No of entries in tag predictors = " << numTagPredEntries << endl;

        for (uint32_t ii = 0; ii < NUMTAGTABLES; ii++) {
            tagPred[ii] = new TagEntry[numTagPredEntries];
        }
        for (uint32_t ii = 0; ii < NUMTAGTABLES; ii++) {
            for (uint32_t j = 0; j < numTagPredEntries; j++) {
                tagPred[ii][j].ctr = 0;
                tagPred[ii][j].tag = 0;
                tagPred[ii][j].usefulBits = 0;
            }

        }

        // Geometric lengths of history taken to consider correlation of different age.
        // Table 0 with the longest history as per PPM code
        geometric[0] = 130;
        geometric[1] = 44;
        geometric[2] = 15;
        geometric[3] = 5;
        /*this gives 3.41 MPKI !!
         * geometric[0] = 200;
        geometric[1] = 80;
        geometric[2] = 20;
        geometric[3] = 5;*/

        // Initializing Compressed Buffers.
        // first for index of the the tagged tables
        for (int k = 0; k < 2 /*SMT*/; k++){
            for (int i = 0; i < NUMTAGTABLES; i++) {
                indexComp[k][i].compHist = 0;
                indexComp[k][i].geomLength = geometric[i];
                indexComp[k][i].targetLength = TAGPREDLOG;
            }
        }

        // next for the tag themselves

        // The tables have different tag lengths
        // T2 and T3 have tag length -> 8
        // T0 and T1 have tag length -> 9
        // second index indicates the Bank no.
        // Reason for using two -> PPM paper... single
        // CSR is sensitive to periodic patterns in global history which is a common case
        for (int k = 0; k < 2 /*SMT*/; k++){
            for (int j = 0; j < 2; j++) {
                for (int i = 0; i < NUMTAGTABLES; i++) {
                    tagComp[k][j][i].compHist = 0;
                    tagComp[k][j][i].geomLength = geometric[i];
                    if (j == 0) {
                        if (i < 2)
                            tagComp[k][j][i].targetLength = 9;
                        else
                            tagComp[k][j][i].targetLength = 9;
                    } else {
                        if (i < 2)
                            tagComp[k][j][i].targetLength = 8;
                        else
                            tagComp[k][j][i].targetLength = 8;
                    }
                }
            }
        }
        // Preditions banks and prediction values
        primePred = -1;
        altPred = -1;
        primeBank = NUMTAGTABLES;
        altBank = NUMTAGTABLES;

        for (int i = 0; i < NUMTAGTABLES; i++) {
            indexTagPred[i] = 0;
        }
        for (int i = 0; i < NUMTAGTABLES; i++) {
            tag[i] = 0;
        }
        clock = 0;
        clock_flip = 1;
        for (int k = 0; k < 2 /*SMT*/; k++){
            PHR[k] = 0;
            GHR[k].reset();
        }
        altBetterCount = 8;
    }

    bool GetPrediction(uint32_t PC, uint32_t thread) {
        /// Base Prediction

        bool basePrediction;
        uint32_t bimodalIndex = (PC) % (numBimodalEntries);
        uint32_t bimodalCounter = bimodal[bimodalIndex];

        if (bimodalCounter > BIMODAL_CTR_MAX / 2) {
            basePrediction = 1;
        } else {
            basePrediction = 0;
        }

        // Hash to get tag includes info about bank, pc and global history compressed

        // formula given in PPM paper
        // pc[9:0] xor CSR1 xor (CSR2 << 1)
        for (int i = 0; i < NUMTAGTABLES; i++) {
            tag[i] = PC ^ tagComp[thread][0][i].compHist ^ (tagComp[thread][1][i].compHist << 1);
            /// These need to be masked
            // 9 bit tags for T0 and T1 // 8 bit tags for T2 and T3
        }
        tag[0] &= ((1 << 9) - 1);
        tag[1] &= ((1 << 9) - 1);
        tag[2] &= ((1 << 9) - 1);
        tag[3] &= ((1 << 9) - 1);
        // Tags now ready

        // How to get index for each bank ??
        // bank 1
        // Hash of PC, PC >> index length important , GHR geometric, path info
        uint32_t index_mask = ((1 << TAGPREDLOG) - 1);


        /*indexTagPred[0] = PC ^ (PC >> TAGPREDLOG) ^ indexComp[0].compHist ^ PHR ^ (PHR >> TAGPREDLOG);
        indexTagPred[1] = PC ^ (PC >> TAGPREDLOG) ^ indexComp[1].compHist ^ PHR ^ (PHR >> TAGPREDLOG);
        indexTagPred[2] = PC ^ (PC >> TAGPREDLOG) ^ indexComp[2].compHist ^ PHR ^ (PHR >> TAGPREDLOG);
        indexTagPred[3] = PC ^ (PC >> TAGPREDLOG) ^ indexComp[3].compHist ^ PHR ^ (PHR >> TAGPREDLOG);*/
        indexTagPred[0] = PC ^ (PC >> TAGPREDLOG) ^ indexComp[thread][0].compHist ^ PHR[thread] ^ (PHR[thread] >> TAGPREDLOG);
        indexTagPred[1] = PC ^ (PC >> (TAGPREDLOG - 1)) ^ indexComp[thread][1].compHist ^ (PHR[thread]);
        indexTagPred[2] = PC ^ (PC >> (TAGPREDLOG - 2)) ^ indexComp[thread][2].compHist ^ (PHR[thread] & 31);
        indexTagPred[3] = PC ^ (PC >> (TAGPREDLOG - 3)) ^ indexComp[thread][3].compHist ^
                          (PHR[thread] & 7);  // 1 & 63 gives 3.358 // shuttle 31 and 15: 3.250 //ece 31 and 1: 3.252
        /// These need to be masked   // shuttle : 1023 63 and 15: 3.254 // ece 1023, 31 and 1 : 3.254
        ////  63 and 7  and PC  -2 -4 -6 // 63 and 1 gives 3.256  // 63 and 7 s: // 31 and 7 : 3.243 best !
        for (int i = 0; i < NUMTAGTABLES; i++) {
            indexTagPred[i] = indexTagPred[i] & index_mask;

        }

        // get two predictions prime and alt (alternate)
        primePred = -1;
        altPred = -1;
        primeBank = NUMTAGTABLES;
        altBank = NUMTAGTABLES;

        /// See if any tag matches
        // T0 with longest history so if hit that awesome

        for (int iterator = 0; iterator < NUMTAGTABLES; iterator++) {


            if (tagPred[iterator][indexTagPred[iterator]].tag == tag[iterator]) {
                primeBank = iterator;
                break;
            }
        }
        for (int iterator = primeBank + 1; iterator < NUMTAGTABLES; iterator++) {
            if (tagPred[iterator][indexTagPred[iterator]].tag == tag[iterator]) {
                altBank = iterator;
                break;
            }
        }


        if (primeBank < NUMTAGTABLES) {
            if (altBank == NUMTAGTABLES) {
                altPred = basePrediction;
            } else {
                if (tagPred[altBank][indexTagPred[altBank]].ctr >= TAGPRED_CTR_MAX / 2)
                    altPred = TAKEN;
                else
                    altPred = NOT_TAKEN;
            }

            if ((tagPred[primeBank][indexTagPred[primeBank]].ctr != 3) ||
                (tagPred[primeBank][indexTagPred[primeBank]].ctr != 4) ||
                (tagPred[primeBank][indexTagPred[primeBank]].usefulBits != 0) || (altBetterCount < 8)) {
                if (tagPred[primeBank][indexTagPred[primeBank]].ctr >= TAGPRED_CTR_MAX / 2)
                    primePred = TAKEN;
                else
                    primePred = NOT_TAKEN;
                predDir = primePred;
                return primePred;
            } else {
                predDir = altPred;
                return altPred;
            }
        } else {
            altPred = basePrediction;
            predDir = altPred;
            return altPred;
        }
    }

    void UpdatePredictor(uint32_t PC, bool resolveDir, uint32_t branchTarget, uint32_t thread) {
        bool strong_old_present = false;
        bool new_entry = 0;
        if (primeBank < NUMTAGTABLES) {
            // As per update policy
            // 1st update the useful counter
            if ((predDir != altPred)) {

                if (predDir == resolveDir) {

                    tagPred[primeBank][indexTagPred[primeBank]].usefulBits = SatIncrement(
                            tagPred[primeBank][indexTagPred[primeBank]].usefulBits, BIMODAL_CTR_MAX);

                } else {
                    tagPred[primeBank][indexTagPred[primeBank]].usefulBits = SatDecrement(
                            tagPred[primeBank][indexTagPred[primeBank]].usefulBits);
                }

            }
            // 2nd update the counters which provided the prediction  
            if (resolveDir) {
                tagPred[primeBank][indexTagPred[primeBank]].ctr = SatIncrement(
                        tagPred[primeBank][indexTagPred[primeBank]].ctr, TAGPRED_CTR_MAX);
            } else {
                tagPred[primeBank][indexTagPred[primeBank]].ctr = SatDecrement(
                        tagPred[primeBank][indexTagPred[primeBank]].ctr);
            }
        } else {
            uint32_t bimodalIndex = (PC) % (numBimodalEntries);
            if (resolveDir) {
                bimodal[bimodalIndex] = SatIncrement(bimodal[bimodalIndex], BIMODAL_CTR_MAX);
            } else {
                bimodal[bimodalIndex] = SatDecrement(bimodal[bimodalIndex]);
            }
        }
        // Check if the current Entry which gave the prediction is a newly allocated entry or not.
        if (primeBank < NUMTAGTABLES) {

            if ((tagPred[primeBank][indexTagPred[primeBank]].usefulBits == 0) &&
                ((tagPred[primeBank][indexTagPred[primeBank]].ctr == 3) ||
                 (tagPred[primeBank][indexTagPred[primeBank]].ctr == 4))) {
                new_entry = true;

                if (primePred != altPred) {
                    if (altPred == resolveDir) {
// Alternate prediction more useful is a counter to be of 4 bits
                        if (altBetterCount < 15) {
                            altBetterCount++;
                        }
                    } else if (altBetterCount > 0) {
                        altBetterCount--;
                    }
                }
            }
        }


// Proceeding to allocation of the entry.
        if ((!new_entry) || (new_entry && (primePred != resolveDir))) {
            if (((predDir != resolveDir) & (primeBank > 0))) {

                for (int i = 0; i < primeBank; i++) {
                    if (tagPred[i][indexTagPred[i]].usefulBits == 0);
                    strong_old_present = true;

                }
// If no entry useful than decrease useful bits of all entries but do not allocate
                if (strong_old_present == false) {
                    for (int i = primeBank - 1; i >= 0; i--) {
                        tagPred[i][indexTagPred[i]].usefulBits--;
                    }
                } else {

                    // srand(time(NULL));
                    // int randNo = rand() % 100;
                    int randNo = MYRANDOM() % 100;
                    int count = 0;
                    int bank_store[NUMTAGTABLES - 1] = {-1, -1, -1};
                    int matchBank = 0;
                    for (int i = 0; i < primeBank; i++) {
                        if (tagPred[i][indexTagPred[i]].usefulBits == 0) {
                            count++;
                            bank_store[i] = i;
                        }
                    }
                    if (count == 1) {
                        matchBank = bank_store[0];
                    } else if (count > 1) {
                        if (randNo > 33 && randNo <= 99) {
                            matchBank = bank_store[(count - 1)];
                        } else {
                            matchBank = bank_store[(count - 2)];
                        }
                    }


                    for (int i = matchBank; i > -1; i--) {
                        if ((tagPred[i][indexTagPred[i]].usefulBits == 0)) {
                            if (resolveDir) {
                                tagPred[i][indexTagPred[i]].ctr = 4;
                            } else {
                                tagPred[i][indexTagPred[i]].ctr = 3;
                            }
                            tagPred[i][indexTagPred[i]].tag = tag[i];
                            tagPred[i][indexTagPred[i]].usefulBits = 0;
                            break; // Only 1 entry allocated
                        }
                    }

                }

            }
        }


// Periodic Useful bit Reset Logic ( Important so as to optimize compared to PPM paper)
        clock++;
        //for every 256 K instruction 1st MSB than LSB
        if (clock == (256 * 1024)) {
            // reset clock
            clock = 0;
            if (clock_flip == 1) {
                // this is the 1st time
                clock_flip = 0;
            } else {
                clock_flip = 1;
            }
            if (clock_flip == 1) {// MSB turn
                for (int jj = 0; jj < NUMTAGTABLES; jj++) {
                    for (uint32_t ii = 0; ii < numTagPredEntries; ii++) {
                        tagPred[jj][ii].usefulBits = tagPred[jj][ii].usefulBits & 1;
                    }
                }
            } else {// LSB turn
                for (int jj = 0; jj < NUMTAGTABLES; jj++) {
                    for (uint32_t ii = 0; ii < numTagPredEntries; ii++) {
                        tagPred[jj][ii].usefulBits = tagPred[jj][ii].usefulBits & 2;
                    }
                }

            }

        }


        // update the GHR
        GHR[thread] = (GHR[thread] << 1);

        if (resolveDir == TAKEN) {
            GHR[thread].set(0, 1);
        }

        for (int i = 0; i < NUMTAGTABLES; i++) {

            indexComp[thread][i].updateCompHist(GHR[thread]);
            tagComp[thread][0][i].updateCompHist(GHR[thread]);
            tagComp[thread][1][i].updateCompHist(GHR[thread]);

        }
        // PHR update is simple, jus take the last bit ??
        // Always Limited to 16 bits as per paper.
        PHR[thread] = (PHR[thread] << 1);
        if (PC & 1) {
            PHR[thread] = PHR[thread] + 1;
        }
        PHR[thread] = (PHR[thread] & ((1 << 16) - 1));
    }

//    void TrackOtherInst(uint32_t PC, OpType opType, uint32_t branchTarget);

    // Contestants can define their own functions below

};


TagePredictor tage_predictors[NUM_CPUS];


void O3_CPU::initialize_branch_predictor() {
    cout << "CPU " << cpu << " Tage branch predictor" << endl;
}

// uint8_t O3_CPU::predict_branch(uint64_t ip, uint64_t predicted_target, uint8_t always_taken, uint8_t branch_type, uint32_t thread) {
uint8_t O3_CPU::predict_branch(uint64_t ip) {
    return tage_predictors[cpu].GetPrediction(ip,0) ? 1 : 0;
    // return tage_predictors[cpu].GetPrediction(ip,0) ? 1 : 0;
}

// void O3_CPU::last_branch_result(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type, uint32_t thread) {
void O3_CPU::last_branch_result(uint64_t ip, uint64_t branch_target, uint8_t taken, uint8_t branch_type) {
    tage_predictors[cpu].UpdatePredictor(ip, (taken != 0), branch_target,0);
    // tage_predictors[cpu].UpdatePredictor(ip, (taken != 0), branch_target,thread);
}
