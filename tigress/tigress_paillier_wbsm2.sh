#!/bin/bash
tigress --Seed=66 --Statistics=0 --Verbosity=1 --Environment=x86_64:Linux:Gcc:4.6  \
     --Transform=InitEntropy \
        --Functions=paillier_wbsm2_sig_with_hash \
        --InitEntropyKinds=vars \
     --Transform=InitOpaque \
        --Functions=paillier_wbsm2_sig_with_hash \
        --InitOpaqueStructs=list,array,env  \
     --Transform=Virtualize \
        --VirtualizeDispatch=direct \
        --Functions=paillier_wbsm2_sig_with_hash \
     --Transform=EncodeLiterals \
        --Functions=paillier_wbsm2_sig_with_hash \
     --Transform=SelfModify \
        --Skip=true \
        --Functions=paillier_wbsm2_sig_with_hash \
        --SelfModifySubExpressions=false \
        --SelfModifyBogusInstructions=100 \
    --out=./paillier_wbsm2_obs.c ./paillier_wbsm2.c -lrelic_s

 ./a.out

 rm a.out
