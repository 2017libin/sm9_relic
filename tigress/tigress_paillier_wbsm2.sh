#!/bin/bash
tigress --Seed=66 --Statistics=0 --Verbosity=1 --Environment=x86_64:Linux:Gcc:4.6  \
     --Transform=InitEntropy \
        --Functions=sig_t \
        --InitEntropyKinds=vars \
     --Transform=InitOpaque \
        --Functions=sig_t \
        --InitOpaqueStructs=list,array,env  \
     --Transform=Virtualize \
        --VirtualizeDispatch=direct \
        --Functions=sig_t \
     --Transform=EncodeLiterals \
        --Functions=sig_t \
     --Transform=SelfModify \
        --Skip=true \
        --Functions=sig_t \
        --SelfModifySubExpressions=false \
        --SelfModifyBogusInstructions=100 \
    --out=./paillier_wbsm2_out.c ./paillier_wbsm2.c -lrelic_s

 ./a.out

 rm a.out
