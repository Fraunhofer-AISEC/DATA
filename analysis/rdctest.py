"""
Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC

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
# @license This project is released under the GNU GPLv3+ License.
# @author See AUTHORS file.
# @version 0.3


import fcntl
import numpy
import warnings
import pickle
from datastub.utils import debug
from scipy.stats import rankdata, pearsonr, norm
from scipy.optimize import curve_fit
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
    def test(Inputs, Observations, Confidence, max_iter=100):
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
            debug(1, "Constant input/observations")
            return (None, None, None)

        # constant input/observations
        if len(Observations) < 30:
            debug(1, "Less than 30 observations")
            return (None, None, None)

        # varying input/observations
        else:
            (R, L, I) = RDC.rdc(
                Inputs, Observations, Confidence, SkipThres=False, max_iter=max_iter
            )
            return (R, L, I)

    ###
    # Approximate Significance Threshold
    # based on curve fitting (Alpha=0.9999)
    ###
    def rdc_sigthres_approximate(N, Alpha):

        if Alpha != 0.9999:
            return None

        if N < 30 or N > 10000:
            raise ValueError("N out of known bounds")

        # We fit two asymmetric sigmoidal functions to the measurements
        # They overlap to some degree
        cutoff = 500

        # fmt: off
        lookup0_500 = {
            30: 1.000000,   40: 0.923018,   50: 0.835880,   60: 0.767314, # noqa
            70: 0.713653,   80: 0.672781,   90: 0.634225,  100: 0.577012, # noqa
           110: 0.573267,  120: 0.550929,  130: 0.528235,  140: 0.511403, # noqa
           150: 0.493248,  160: 0.479536,  170: 0.462665,  180: 0.451899, # noqa
           190: 0.439313,  200: 0.412255,  210: 0.419408,  220: 0.407905, # noqa
           230: 0.397877,  240: 0.389157,  250: 0.381936,  260: 0.374531, # noqa
           270: 0.371447,  280: 0.360654,  290: 0.354491,  300: 0.350278, # noqa
           310: 0.343973,  320: 0.337371,  330: 0.334199,  340: 0.328134, # noqa
           350: 0.324156,  360: 0.319285,  370: 0.314948,  380: 0.310029, # noqa
           390: 0.307529,  400: 0.301025,  410: 0.300683,  420: 0.296257, # noqa
           430: 0.291929,  440: 0.288305,  450: 0.285181,  460: 0.282713, # noqa
           470: 0.279795,  480: 0.277395,  490: 0.274330,  500: 0.262624, # noqa
           550: 0.258773,  600: 0.247494,  650: 0.238005,  700: 0.229496, # noqa
           750: 0.222045,  800: 0.213325,  850: 0.207487,  900: 0.202634, # noqa
           950: 0.195773, 1000: 0.186797, 1100: 0.181741, 1200: 0.174593, # noqa
          1300: 0.168007, 1400: 0.160386, 1500: 0.155562,                 # noqa
        }

        lookup500_10k = {
           400: 0.301025,  410:  0.300683,  420: 0.296257,  430: 0.291929, # noqa
           440: 0.288305,  450:  0.285181,  460: 0.282713,  470: 0.279795, # noqa
           480: 0.277395,  490:  0.274330,  500: 0.262624,  550: 0.258773, # noqa
           600: 0.247494,  650:  0.238005,  700: 0.229496,  750: 0.222045, # noqa
           800: 0.213325,  850:  0.207487,  900: 0.202634,  950: 0.195773, # noqa
          1000: 0.186797, 1100:  0.181741, 1200: 0.174593, 1300: 0.168007, # noqa
          1400: 0.160386, 1500:  0.155562, 1600: 0.150145, 1700: 0.145562, # noqa
          1800: 0.141778, 1900:  0.137554, 2000: 0.131488, 2100: 0.131099, # noqa
          2200: 0.127573, 2300:  0.125372, 2400: 0.123415, 2500: 0.120135, # noqa
          2600: 0.117645, 2700:  0.114993, 2800: 0.112821, 2900: 0.110454, # noqa
          3000: 0.109174, 3100:  0.107230, 3200: 0.106154, 3300: 0.104003, # noqa
          3400: 0.102656, 3500:  0.101157, 3600: 0.099424, 3700: 0.097851, # noqa
          3800: 0.096591, 3900:  0.095751, 4000: 0.094457, 4100: 0.092269, # noqa
          4200: 0.091654, 4300:  0.090859, 4400: 0.089608, 4500: 0.088367, # noqa
          4600: 0.087721, 4700:  0.086456, 4800: 0.086405, 4900: 0.084792, # noqa
          5000: 0.084037, 5200:  0.082346, 5400: 0.080880, 5600: 0.079060, # noqa
          5800: 0.077509, 6000:  0.076448, 6200: 0.075184, 6400: 0.073511, # noqa
          6600: 0.072969, 6800:  0.071680, 7000: 0.070908, 7200: 0.069603, # noqa
          7400: 0.068502, 7600:  0.067860, 7800: 0.067060, 8000: 0.066366, # noqa
          8200: 0.065299, 8400:  0.064779, 8600: 0.063913, 8800: 0.063217, # noqa
          9000: 0.062176, 9200:  0.061583, 9400: 0.060947, 9600: 0.060281, # noqa
          9800: 0.059802, 10000: 0.0588479,                                # noqa
        } # noqa
        # fmt: on

        Xl = [k for k in lookup0_500.keys()]
        Xl.sort()
        Yl = [float(lookup0_500[x]) for x in Xl]

        Xh = [k for k in lookup500_10k.keys()]
        Xh.sort()
        Yh = [float(lookup500_10k[x]) for x in Xh]

        def asymsigmoid(x, a, b, c, d, e):
            # Asymmetric sigmoid
            return d + (a - d) / (1 + (x / c) ** b) ** e

        fit = False

        if fit:
            # Fit two asymmetric sigmoidal functions to the measurements
            poptl, pcovl = curve_fit(
                asymsigmoid, Xl, Yl, bounds=(0, [2, 200, 100, 1, 1])
            )
            popth, pcovh = curve_fit(asymsigmoid, Xh, Yh, bounds=(0, [200, 5, 1, 1, 1]))
        else:
            # Cached for efficiency
            poptl = [
                1.0405813870371978,
                5.906516651519792,
                32.67925715067476,
                7.420936678471437e-19,
                0.08354565093830184,
            ]
            popth = [
                80.45137912486614,
                2.1786178713255144,
                0.006666093739093521,
                1.2161893230883887e-16,
                0.23285829194616056,
            ]

        if False:  # Plot
            # Single curve fitting
            lookup = lookup0_500.copy()
            lookup.update(lookup500_10k)
            X = [k for k in lookup.keys()]
            X.sort()
            Y = [float(lookup[x]) for x in X]
            popt, pcov = curve_fit(asymsigmoid, X, Y, bounds=(0, [2, 5, 100, 1, 1]))

            import numpy as np
            import matplotlib.pyplot as plt

            # Plot original data points
            plt.plot(X, Y, "o")

            # Plot single curve fitting
            new = np.linspace(min(X), max(X), num=10000, endpoint=True)
            plt.plot(new, asymsigmoid(new, *popt), "r-")

            # Plot double curve fitting
            newl = np.linspace(min(Xl), cutoff, num=10000, endpoint=True)
            newh = np.linspace(cutoff, max(Xh), num=10000, endpoint=True)
            # ~ newl = np.linspace(min(Xl), max(Xl), num=10000, endpoint=True)
            # ~ newh = np.linspace(min(Xh), max(Xh), num=10000, endpoint=True)
            plt.plot(newl, asymsigmoid(newl, *poptl), "b-")
            plt.plot(newh, asymsigmoid(newh, *popth), "g-")
            plt.show()

        if N <= 30:
            return 1.0
        if N < cutoff:
            return asymsigmoid(N, *poptl)
        else:
            return asymsigmoid(N, *popth)

    ###
    # Compute Significance Threshold
    ###
    @staticmethod
    def rdc_sigthres_compute(N, Alpha):
        """
        Computes the significance threshold for the RDC.

        Keyword arguments:
        N     -- Number of measurement samples
        Alpha -- The required confidence level (0 < Alpha < 1)

        Returns:
        L -- Significance level
        """

        # compute sigthres level
        l = 10000
        v = numpy.zeros(l, dtype=numpy.float)
        for i in range(0, l):
            a = numpy.random.normal(size=N)
            b = numpy.random.normal(size=N)
            R = None
            while R is None:
                debug(
                    2,
                    "rdc_limit computation for N=%d, alpha=%f, iteration %d/%d",
                    (N, Alpha, i, l),
                )
                (R, _, _) = RDC.rdc(a, b, Alpha, SkipThres=True, max_iter=-1)
                # With max_iter=-1, R is always != None
            v[i] = R
        (mu, std) = norm.fit(v)
        L = norm.isf(1.0 - Alpha, loc=mu, scale=std)
        L = numpy.min([L, 1.0])

        debug(1, "New rdc_limit: Alpha=%.6f, N=%d, L=%.6f", (Alpha, N, L))
        return L

    ###
    # Retrieve RDC Significance Threshold
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

        if Alpha == 0.9999:
            # Use precomputed parameters
            try:
                return RDC.rdc_sigthres_approximate(N, Alpha)
            except:
                # Maybe N is too large
                debug(2, "rdc_sigthres_approximate fallthrough")
                pass

        # check pre-computed
        if Alpha in RDC.RDC_SIGTHRES.keys():
            if N in RDC.RDC_SIGTHRES[Alpha].keys():
                return RDC.RDC_SIGTHRES[Alpha][N]

        # fill from file

        # Maybe, another parallel process filled it in already,
        # so we always reload the pickle file
        # if not RDC.RDC_SIGTHRES_FLOAD:
        if True:
            try:
                d = None
                with open("rdcst.pickle", "rb") as f:
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
        L = RDC.rdc_sigthres_compute(N, Alpha)

        # save value
        if Alpha not in RDC.RDC_SIGTHRES.keys():
            RDC.RDC_SIGTHRES[Alpha] = {}
        RDC.RDC_SIGTHRES[Alpha][N] = L

        # store dictionary
        try:
            with open("rdcst.pickle", "wb") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                pickle.dump(RDC.RDC_SIGTHRES, f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except:
            debug(0, "Failed to store RDC significance threshold dictionary")

        return L

    ###
    # Randomized Dependence Coefficient - RDC
    ###
    @staticmethod
    def rdc(X, Y, Alpha, SkipThres=False, max_iter=-1):
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
        s1 = 1.0 / 6.0
        s2 = 1.0 / 6.0

        # sanity check
        if X.size != Y.size:
            raise Exception("Size of X and Y must be equal to compute the RDC!")

        # init
        (n1, n2) = (X.size, Y.size)
        t1 = numpy.ones((n1, 2), dtype=numpy.float)
        t2 = numpy.ones((n2, 2), dtype=numpy.float)
        t3 = numpy.ones((n1, k + 1), dtype=numpy.float)
        t4 = numpy.ones((n2, k + 1), dtype=numpy.float)

        # normalized rank
        t1[:, 0] = rankdata(X) / float(n1)
        t2[:, 0] = rankdata(Y) / float(n2)

        # scale
        t1 *= s1 / 2.0
        t2 *= s2 / 2.0

        it = 1
        while True:
            if max_iter > 0 and it > max_iter:
                debug(2, "RDC: Too many iterations, aborting")
                return (None, None, None)
            it += 1

            # random sampling
            r1 = numpy.random.normal(size=(2, k))
            r2 = numpy.random.normal(size=(2, k))

            # multiply and sinus
            t3[:, :k] = numpy.sin(numpy.dot(t1, r1))
            t4[:, :k] = numpy.sin(numpy.dot(t2, r2))

            # canonical correlation
            cca = CCA(n_components=1)
            scx = None
            scy = None
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                scx, scy = cca.fit_transform(t3, t4)

            # sanity check
            if numpy.var(scx[:, 0]) == 0 or numpy.var(scy[:, 0]) == 0:
                continue
            else:
                break

        # calc Pearson
        try:
            R = pearsonr(scx[:, 0], scy[:, 0])[0]
        except:
            return (None, None, None)

        # sig thres
        if SkipThres:
            return (R, None, None)
        else:
            L = RDC.rdc_sigthres(n1, Alpha)
            I = R <= L
            return (R, L, I)
