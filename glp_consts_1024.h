/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef GLP_CONSTS_1024_H
#define GLP_CONSTS_1024_H

#include <stdio.h>
#include <math.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#if (GLP_N != 1024)
#error GLP_N
#endif

#define NISPOWEROFTWO 1

#define Q 59393
#define N 1024
#define OMEGA 16
#define B 16383
#define B_BITS 14
#define Q_BITS 16
#define Q_BYTES 2
#define NBITS 10

static const RINGELT a[N] = {
36543, 57297, 41004, 34957, 39295, 24272, 16205, 32656, 54664, 50605, 32248, 762, 24420, 19183, 21742, 38043, 48850, 3753, 12712, 11913, 7938, 5533, 15665, 39145, 33798, 49338, 20531, 16278, 46749, 24662, 49168, 48626, 11866, 49407, 52400, 30070, 3533, 39188, 18692, 41253, 47063, 46267, 6853, 39213, 43062, 52952, 13831, 19762, 49921, 36609, 9092, 24887, 8001, 14250, 7044, 36587, 28121, 16242, 23883, 21196, 42465, 38953, 12943, 38356, 3756, 25206, 5404, 13345, 6773, 364, 906, 36632, 27100, 28815, 32057, 3581, 44697, 53662, 10405, 12729, 40348, 19512, 55903, 23396, 16650, 3897, 9748, 17962, 1719, 39694, 24023, 3243, 25586, 27805, 7341, 37960, 30906, 17889, 44324, 50675, 34499, 16921, 22982, 35979, 11015, 55237, 36131, 39143, 49996, 25194, 3397, 7589, 30934, 49588, 7086, 16057, 24909, 40461, 5028, 46375, 11111, 22036, 46216, 14857, 57052, 18114, 21790, 9694, 7327, 27270, 14247, 22616, 50322, 1607, 58531, 7360, 2255, 55502, 18653, 57240, 878, 52083, 12630, 23971, 9662, 54144, 26315, 36516, 34165, 21950, 49261, 46133, 21855, 20024, 32948, 6906, 13193, 7966, 22240, 29552, 54390, 35390, 10875, 57901, 53498, 1635, 3132, 57266, 37608, 22602, 34170, 18471, 38934, 45516, 24110, 2444, 25068, 46561, 46466, 26287, 17048, 16932, 40433, 21439, 21483, 20068, 30427, 9203, 7888, 31931, 49430, 3251, 27529, 28442, 10645, 9968, 1906, 13748, 38722, 59018, 4881, 2432, 37609, 52073, 21457, 12237, 59315, 5182, 44228, 5004, 14881, 15206, 18704, 58110, 46282, 15260, 16875, 39481, 35728, 55444, 54508, 45460, 39316, 13819, 2230, 11154, 15609, 6555, 34846, 39643, 46467, 24843, 47865, 33808, 58064, 14611, 19489, 7168, 10100, 9060, 58685, 48801, 56242, 50120, 10496, 31524, 38669, 40581, 26129, 9749, 41509, 48874, 3593, 55508, 33607, 58684, 48513, 29842, 28888, 36151, 8535, 46263, 42071, 29495, 36708, 49478, 5045, 13540, 11347, 5437, 17663, 26410, 57423, 7318, 43705, 5686, 13507, 21903, 3794, 43636, 24891, 16120, 46431, 24679, 21464, 8166, 57126, 51768, 54821, 37333, 20725, 10162, 51715, 46946, 11730, 52062, 3287, 34213, 55335, 52678, 34596, 58496, 26251, 44916, 7535, 38345, 5890, 27004, 54713, 9764, 44404, 56867, 20357, 22143, 45125, 38087, 36972, 22880, 6770, 21549, 33630, 58494, 53509, 19971, 39010, 9318, 31331, 4390, 49885, 49014, 848, 54790, 55858, 5453, 24004, 53108, 739, 30969, 13346, 23287, 31527, 6821, 9411, 8649, 12835, 34681, 54693, 37050, 35473, 6136, 43454, 12448, 1123, 22510, 58270, 36340, 4350, 57121, 51036, 9826, 14346, 8725, 30456, 48937, 38280, 46423, 49278, 3977, 6851, 45125, 8111, 56690, 33002, 759, 37760, 26917, 23768, 29280, 48510, 33143, 21203, 57844, 49151, 3972, 45743, 15252, 6993, 39920, 1480, 51056, 56806, 44852, 47079, 36008, 2073, 25001, 11286, 36388, 555, 419, 155, 35778, 16023, 10131, 54044, 39835, 7430, 3417, 40277, 54587, 38657, 38186, 18531, 34630, 28555, 8976, 43657, 1558, 22978, 50564, 45930, 53363, 26278, 54198, 27696, 41953, 47625, 57351, 36174, 56326, 19896, 322, 55447, 45722, 11893, 2764, 4255, 8100, 23730, 23033, 46742, 58141, 36551, 45999, 23942, 56439, 35447, 56705, 2746, 55009, 4770, 48195, 21224, 43505, 49952, 10428, 48766, 26372, 23067, 5886, 7924, 11593, 37724, 50305, 1370, 57936, 13803, 43600, 57049, 16701, 16219, 56558, 49250, 32239, 39304, 36769, 1098, 55282, 9065, 44813, 5277, 23915, 55688, 7468, 48179, 28962, 43643, 53917, 22996, 43026, 29252, 40049, 21777, 14062, 47103, 12839, 53605, 32213, 56106, 46784, 18892, 25620, 17180, 37971, 33252, 15490, 20050, 4594, 19405, 37803, 37531, 30413, 58221, 5186, 17199, 51554, 24274, 3308, 26669, 7953, 22984, 17506, 36337, 47272, 4677, 40427, 52241, 6982, 40336, 44124, 43268, 38842, 30235, 28346, 34886, 5197, 6460, 37199, 836, 2126, 14601, 20534, 20019, 45713, 7429, 54921, 39807, 54549, 27322, 22734, 55611, 46038, 52420, 983, 49451, 24961, 25291, 11222, 51393, 33337, 17122, 45993, 55514, 39047, 26805, 48395, 2588, 4675, 14961, 28477, 46046, 49929, 31213, 19767, 35566, 46970, 11791, 43365, 7115, 1522, 45420, 49457, 459, 52438, 43424, 37051, 48189, 7559, 42799, 10190, 9438, 10949, 867, 49106, 54130, 27896, 25056, 39662, 1142, 18026, 20681, 32299, 53520, 36330, 46525, 58467, 27297, 47584, 45271, 46351, 47806, 48920, 16413, 13358, 17430, 38571, 22321, 38041, 13119, 18515, 51497, 48346, 45585, 6641, 53051, 4637, 30108, 12352, 29800, 40019, 52733, 37597, 3526, 35066, 33608, 13094, 16969, 668, 20317, 1784, 10863, 16350, 43907, 58428, 18533, 21901, 8989, 56200, 15033, 34699, 43879, 12190, 39960, 9817, 23677, 1877, 59047, 56292, 21022, 6871, 23208, 43519, 40674, 34464, 21985, 56253, 19179, 24973, 24548, 28166, 4957, 49639, 12550, 48964, 59361, 23890, 41860, 38913, 7789, 34777, 26226, 31026, 22744, 33520, 23304, 33010, 12471, 55535, 50716, 50399, 3627, 20081, 21924, 25336, 8739, 41720, 51104, 932, 44541, 7918, 50341, 6307, 22890, 29788, 54380, 31235, 1181, 26313, 58201, 5803, 5646, 58549, 15182, 9913, 40711, 35588, 51282, 34969, 45532, 30298, 29762, 56647, 17624, 43362, 11651, 52615, 14040, 17163, 24340, 21773, 32773, 25078, 38741, 13294, 20288, 22390, 14169, 8801, 48858, 30500, 28002, 26528, 44422, 58799, 46749, 56065, 43343, 45266, 26369, 40270, 31001, 13767, 38417, 21695, 29881, 26612, 2771, 19978, 44538, 42367, 51586, 57702, 46070, 9777, 42595, 12194, 19543, 24381, 56034, 49849, 38880, 3556, 16426, 32488, 1453, 12997, 41327, 24695, 39799, 37539, 2362, 21340, 24989, 48485, 38574, 38984, 12701, 55898, 56139, 42199, 42593, 13369, 5408, 17116, 39452, 29690, 52411, 39138, 15955, 13890, 47114, 21054, 18918, 2601, 29427, 17933, 34446, 8592, 31792, 3647, 52309, 33845, 27084, 331, 11059, 18062, 30995, 12536, 57078, 44008, 13394, 47468, 52525, 21329, 10323, 5493, 26640, 34775, 33430, 6187, 32709, 22652, 38322, 45456, 51106, 44224, 39216, 13796, 4226, 46427, 11888, 2616, 33004, 20208, 17328, 46690, 25555, 57562, 11048, 48676, 22592, 32399, 40622, 28778, 24960, 38993, 36751, 18930, 32381, 19912, 13348, 3295, 41128, 58372, 22895, 46207, 45899, 35099, 18893, 21583, 30100, 18832, 58083, 54049, 46546, 16497, 59174, 51309, 52822, 58259, 13548, 45199, 51072, 15022, 14798, 22964, 48166, 9280, 45604, 39668, 55862, 27671, 7271, 44108, 23374, 58843, 56660, 56314, 32611, 8556, 50501, 9580, 39961, 51498, 11509, 13239, 36421, 4342, 11271, 33545, 37661, 5697, 55873, 47793, 21387, 2492, 25867, 19690, 6795, 26918, 58197, 48179, 29257, 14035, 28895, 32631, 34723, 56792, 25996, 25511, 17659, 44274, 36701, 58586, 21251, 7007, 36715, 51531, 22760, 52286, 22796, 36057, 16284, 13620, 45028, 59020, 54054, 34085, 7894, 18838, 13364, 18913, 55721, 59053, 29836, 15329, 30088, 6778, 53014, 59215, 25349, 54656, 20303, 11980, 47312, 3912, 53956, 17650, 2449, 42791, 7657, 31597, 40794, 17992, 4627, 25803, 50627, 37890, 58909, 38513, 39766, 53234, 6860, 58327, 38172, 16328, 28543, 22788, 41402, 53286, 52489, 28105, 30543, 5201, 23380, 14162, 33356, 47911, 49995, 1935, 11411, 39382, 13555, 52526, 728, 47012, 35038, 49695, 38777, 57125, 20041, 1897, 56581, 49703, 29994, 27088, 7303, 50861, 5220, 34314, 40604, 13498, 47750, 2235
};

#include "FFT/FFT_includes.h"

void _FFT_forward_1024_59393(FFTSHORT x[GLP_N]);
void _FFT_backward_1024_59393(FFTSHORT x[GLP_N]);

/*macros for FFTs */
#define FFT_FORWARD(A) _FFT_forward_1024_59393((A))
#define FFT_BACKWARD(A) _FFT_backward_1024_59393((A))

#endif /* GLP_CONSTS_1024_H */
