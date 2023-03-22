'''
Spire.

The contents of this file are subject to the Spire Open-Source
License, Version 1.0 (the ``License''); you may not use
this file except in compliance with the License.  You may obtain a
copy of the License at:

http://www.dsn.jhu.edu/spire/LICENSE.txt 

or in the file ``LICENSE.txt'' found in this distribution.

Software distributed under the License is distributed on an AS IS basis, 
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
for the specific language governing rights and limitations under the 
License.

Spire is developed at the Distributed Systems and Networks Lab,
Johns Hopkins University.

Creators:
  Yair Amir             yairamir@cs.jhu.edu
  Trevor Aron           taron1@cs.jhu.edu
  Amy Babay             babay@pitt.edu
  Thomas Tantillo       tantillo@cs.jhu.edu 
  Sahiti Bommareddy     sahiti@cs.jhu.edu

Major Contributors:
  Marco Platania        Contributions to architecture design 
  Daniel Qian           Contributions to Trip Master and IDS 
 

Contributors:

  Samuel Beckley        Contributions to HMIs

Copyright (c) 2017-2023 Johns Hopkins University.
All rights reserved.

Partial funding for Spire research was provided by the Defense Advanced 
Research Projects Agency (DARPA) and the Department of Defense (DoD).
Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
'''

# Specifies models/other files that are used by the models
# All paths relative to the current folder

config = {
    "per_pkt": {
        # Model trained by per_packet scripts
        "model" : "./../ml/packet/lof_distinct_model.pkl",
        
        # The normalizer used to preprocess input, generated by featurize_per_pkt.py
        "scaler" : "./../ml/packet/lof_scaler.pkl",

        # Ouput log file
        "output": "per_pkt_output.log",
    },
    "aggregate": {
        # The training data generated by featurize_aggregate.py. Used to generate more a comparison to the 
        # "normal" traffic in the output 
        "training_data" : "./../ml/aggregate/features.pkl",

        # List of models (rather than a single one). Each time interval all will be used, and "vote" on a result
        # Ideally using multiple models with different algorithms/parameters decreases the false positive rate.
        "models" : [
             "./../ml/aggregate/model.pkl",
        ],

        # Output log file
        "output": "aggregate_output.log"
    }
}
