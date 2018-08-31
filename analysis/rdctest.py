"""
Copyright (C) 2017-2018
Samuel Weiser (IAIK TU Graz) and Andreas Zankl (Fraunhofer AISEC)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

##
# @package analysis.rdctest
# @file rdctest.py
# @brief Specific leakage test based on the RDC.
# @author Samuel Weiser <samuel.weiser@iaik.tugraz.at>
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the GNU GPLv3 License.
# @version 0.1

"""
*************************************************************************
"""

import numpy
import warnings
import pickle
from utils import debug
from scipy.stats import rankdata,pearsonr,norm
from sklearn.cross_decomposition import CCA

"""
*************************************************************************
"""

####
# Class
###
class RDC(object):
    """
    Specific leakage tests based on detecting linear and
    non-linear relations in input-measurement pairs.
    """

    ###
    # Pre-computed RDC SigThres Levels
    ###
    RDC_SIGTHRES = {}
    RDC_SIGTHRES_FLOAD = False

    ###
    # Specific leakage assessment
    ###
    @staticmethod
    def test(Inputs, Observations, Confidence):
        """
        Checks for specific leakage between inputs and measured
        observations. The given input array contains the stimulations
        chosen by the user. The observation array contains the
        corresponding DBI measurements.
        
        Keyword arguments:
        Inputs       -- 1D-array of chosen input values (Numpy Int Array!)
        Observations -- 1D-array of measurement samples (Numpy Int Array!)
        Confidence   -- The required confidence level (0 ... 1)
    
        Returns:
        R -- Randomized dependence coefficient
        L -- Significance level RDC
        I -- Independence (True=independent, False=dependent, None=inconclusive)
        """
        
        # sanity check
        if len(Inputs) != len(Observations):
            raise Exception("Input and observation arrays must have same length!")
        
        # get sample variance
        ivar = numpy.var(Inputs)
        ovar = numpy.var(Observations)
        
        # constant input/observations
        if ivar == 0.0 or ovar == 0.0:
            return (None, None, None)

        # varying input/observations
        else:
            (R, L, I) = RDC.rdc(Inputs, Observations, Confidence)
            return (R, L, I)
    
    ###
    # RDC Significance Threshold
    ###
    @staticmethod
    def rdc_sigthres(N, Alpha):
        """
        Computes the significance threshold for the RDC.
        
        Keyword arguments:
        N     -- Number of measurement samples
        Alpha -- The required confidence level (0 < Alpha < 1)
    
        Returns:
        L -- Significance level
        """
        
        # fill pre-computed
        if len(RDC.RDC_SIGTHRES.keys()) == 0:
            RDC.RDC_SIGTHRES[0.9999] = {100:  0.5770115, 200:   0.4122545, 500:  0.2626236, # <1000:  based on 10^5 repetitions
                                        1000: 0.1867971, 2000:  0.1314884, 5000: 0.0833940, # >=1000: based on 10^4 repetitions
                                        8000: 0.0658570, 10000: 0.0588479}
        
        # fill from file
        if not RDC.RDC_SIGTHRES_FLOAD:
            try:
                d = None
                with open('rdcst.pickle', 'rb') as f:
                    d = pickle.load(f)
                for c in d.keys():
                    for n in d[c].keys():
                        if c not in RDC.RDC_SIGTHRES.keys():
                            RDC.RDC_SIGTHRES[c] = {}
                        if n not in RDC.RDC_SIGTHRES[c].keys():
                            RDC.RDC_SIGTHRES[c][n] = d[c][n]
                RDC.RDC_SIGTHRES_FLOAD = True
            except:
                RDC.RDC_SIGTHRES_FLOAD = True

        # check pre-computed
        if Alpha in RDC.RDC_SIGTHRES.keys():
            if N in RDC.RDC_SIGTHRES[Alpha].keys():
                return RDC.RDC_SIGTHRES[Alpha][N]
        
        # compute sigthres level
        l = 10000
        v = numpy.zeros(l, dtype=numpy.float)
        for i in range(0, l):
            a = numpy.random.normal(size=N)
            b = numpy.random.normal(size=N)
            (R, _, _) = RDC.rdc(a, b, Alpha, SkipThres=True)
            v[i] = R
        (mu,std) = norm.fit(v)
        L = norm.isf(1.0-Alpha, loc=mu, scale=std)
        L = numpy.min([L, 1.0])
        
        # save value
        if Alpha not in RDC.RDC_SIGTHRES.keys():
            RDC.RDC_SIGTHRES[Alpha] = {}
        RDC.RDC_SIGTHRES[Alpha][N] = L
        debug(0, "New RDC significance threshold: Alpha=%.6f, N=%d, L=%.6f", (Alpha, N, L))
        
        # store dictionary
        try:
            with open('rdcst.pickle', 'wb') as f:
                pickle.dump(RDC.RDC_SIGTHRES, f)
        except:
            debug(0, "Failed to store RDC significance threshold dictionary")
        
        # return
        return (L)
        
    ###
    # Randomized Dependence Coefficient - RDC
    ###
    @staticmethod
    def rdc(X, Y, Alpha, SkipThres=False):
        """
        Computes the Randomized Dependence Coefficient (RDC)
        between the two given 1-D arrays. Note: both input
        arrays must have non-zero variance!
        
        Keyword arguments:
        X         -- 1D-array of measurement samples (Numpy Array!)
        Y         -- 1D-array of measurement samples (Numpy Array!)
        Alpha     -- The required confidence level (0 < Alpha < 1)
        SkipThres -- Skip the significance threshold check
    
        Returns:
        R -- Randomized dependence coefficient
        L -- Significance level
        I -- Independence (True=independent, False=dependent)
        """
        
        # RDC params
        k = 20
        s1 = 1./6.
        s2 = 1./6.

        # sanity check
        if X.size != Y.size:
            raise Exception("Size of X and Y must be equal to compute the RDC!")

        # init
        (n1, n2) = (X.size, Y.size)
        t1 = numpy.ones((n1,2), dtype=numpy.float)
        t2 = numpy.ones((n2,2), dtype=numpy.float)
        t3 = numpy.ones((n1,k+1), dtype=numpy.float)
        t4 = numpy.ones((n2,k+1), dtype=numpy.float)

        # normalized rank
        t1[:,0] = rankdata(X) / float(n1)
        t2[:,0] = rankdata(Y) / float(n2)

        # scale
        t1 *= (s1/2.)
        t2 *= (s2/2.)

        while True:
            # random sampling
            r1 = numpy.random.normal(size=(2,k))
            r2 = numpy.random.normal(size=(2,k))

            # multiply and sinus
            t3[:,:k] = numpy.sin(numpy.dot(t1, r1))
            t4[:,:k] = numpy.sin(numpy.dot(t2, r2))
            
            # canonical correlation
            cca = CCA(n_components = 1)
            scx = None
            scy = None
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                scx,scy = cca.fit_transform(t3, t4)
            
            # sanity check
            if numpy.var(scx[:,0]) == 0 or numpy.var(scy[:,0]) == 0:
                continue
            else:
                break

        # calc Pearson
        try:
            R = pearsonr(scx[:,0], scy[:,0])[0]
        except:
            return (None, None, None)

        # sig thres
        if SkipThres:
            return (R, None, None)
        else:
            L = RDC.rdc_sigthres(n1, Alpha)
            I = (R <= L)
            return (R, L, I)

