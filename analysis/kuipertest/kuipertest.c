/************************************************************************
 * Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************/

/**
 * @file kuipertest.c
 * @brief Kuiper test statistic.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

/***
 * Works with latest numpy.
 */
#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION

/***
 * 10e-8 Round Factor
 */
#define RFACT 100000000.0f

/***
 * QKP Zero Limit for 10e-8
 */
#define QKP_START 3.6f

/***
 * Includes.
 */
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <Python.h>
#include <numpy/arrayobject.h>
#include <numpy/npy_math.h>

/************************************************************************/

/**
 * Functions.
 */
int kuipertest_qkp(float l, float* r);
int kuipertest_qkp_inv(float r, float* l);
int kuipertest_kp_hist(int ne, float* x, float* y, int nx, int ny, float c, float* dp, float* dm, float* v, float* l);

/************************************************************************/

/***
 * Q_{KP} function.
 *
 * IN:
 * @param l lambda
 *
 * OUT:
 * @param r = Q_{KP}(l)
 * 
 * @return 0=success, 1=invalid arguments, 2=loop failed
 */
int kuipertest_qkp(float l, float* r)
{
  /* init */
  float cr = 0.0f;
  float pr = 2.0f;
  float t;
  float d;
  int i = 1;

  /* check input */
  if (l <= 0.0f || r == NULL)
    return (1);

  /* calc */
  do {
    /* sum */
    t = pow((float)i, 2) * pow(l, 2);
    cr += (4.0f * t - 1.0f) * exp((-2.0f) * t);

    /* progress */
    d = round(fabs(2*cr-pr) * RFACT) / RFACT;
    i += 1;
    pr = 2*cr;
  } while(d != 0.0f && i > 0);

  /* check and assign */
  if (i < 0)
    return (2);
  cr = round(cr * RFACT) / RFACT;
  *r = cr;

  /* success */
  return (0);
}

/***
 * Q_{KP} inverse function.
 *
 * IN:
 * @param r wanted result
 *
 * OUT:
 * @param l = Q^{-1}_{KP}(r)
 *
 * @return 0=success, 1=invalid arguments, 2=QKP failed, 3=loop failed
 */
int kuipertest_qkp_inv(float r, float* l)
{
  /* init */
  float lc = QKP_START;
  float s = 0.1f;
  float rt;
  float d;
  int i = 0;

  /* check input */
  if (r < 0.0f || r > 1.0f || l == NULL)
    return (1);

  /* calc */
  do {
    /* do one step */
    if (kuipertest_qkp(lc, &rt))
      return (2);
    d = round((r-rt) * RFACT) / RFACT;

    /* adjust step size */
    if (d < 0.0f) {
      lc += s;
      s = s / 10.0f;
    }

    /* progress */
    lc -= s;
    i += 1;
  } while(d != 0.0f && lc > 0.0f && i > 0);

  /* check and assign */
  if (i < 0 || lc <= 0.0f)
    return (3);
  lc = round(lc * RFACT) / RFACT;
  *l = lc;

  /* success */
  return (0);
}

/************************************************************************/

/***
 * Calculates the Kuiper test statistic of two discrete
 * histogram arrays. The length of the histogram arrays must be
 * equal and the histogram entries must be sorted (ascending).
 *
 * IN:
 * @param ne number of entries in x, y
 * @param x histogram 1
 * @param y histogram 2
 * @param nx number of samples in x
 * @param ny number of samples in y
 * @param c confidence level
 *
 * OUT:
 * @param dp D-plus deviation
 * @param dm D-minus deviation
 * @param v KP test statistic
 * @param l significance level
 *
 * @return 0=success, 1=invalid arguments, 2=QKP failed
 */
int kuipertest_kp_hist(int ne, float* x, float* y, int nx, int ny, float c, float* dp, float* dm, float* v, float* l)
{
  /* check inputs */
  if (ne <= 0 || x == NULL || y == NULL || nx < 30 || ny < 30 || c <= 0.0 || c >= 1.0 ||
      dp == NULL || dm == NULL || v == NULL || l == NULL)
    return (1);

  /* init */
  int i;
  float x_cdf, y_cdf;
  float x_scale, y_scale;
  float x_sum, y_sum;
  float diff_plus, diff_minus;
  float dmax_plus, dmax_minus;
  float n;
  float cd;
  float ct;

  /* calc scale factors for x and y */
  x_sum = 0.0f;
  y_sum = 0.0f;
  for (i = 0; i < ne; i++) {
    x_sum += x[i];
    y_sum += y[i];
  }
  x_scale = (x_sum == 0.0f ? 1.0f : (1.0f / x_sum));
  y_scale = (y_sum == 0.0f ? 1.0f : (1.0f / y_sum));

  /* calc significance threshold */
  n = sqrt((float)(nx * ny) / (float)(nx + ny));
  cd = n + 0.155f + (0.24f / n);
  if (kuipertest_qkp_inv(1.0f - c, &ct))
    return (2);
  ct /= cd;

  /* calc CDFs and get max deviation */
  dmax_plus = -2.0f;
  dmax_minus = -2.0f;
  x_cdf = 0.0f;
  y_cdf = 0.0f;
  for (i = 0; i < ne; i++) {
    /* progress in CDF */
    x_cdf += x[i] * x_scale;
    y_cdf += y[i] * y_scale;
    diff_plus = x_cdf - y_cdf;
    diff_minus = y_cdf - x_cdf;

    /* get max deviation */
    if (diff_plus > dmax_plus)
      dmax_plus = diff_plus;
    if (diff_minus > dmax_minus)
      dmax_minus = diff_minus;
  }
  dmax_plus = fmax(dmax_plus, 0.0f);
  dmax_minus = fmax(dmax_minus, 0.0f);

  /* calc KP statistics */
  *dp = dmax_plus;
  *dm = dmax_minus;
  *v = dmax_plus + dmax_minus;
  *l = round(ct * RFACT) / RFACT;

  /* success */
  return (0);
}

/************************************************************************/

/***
 * Calculates the Kuiper test statistic of two discrete
 * histogram arrays. The length of the histogram arrays must be
 * equal and the histogram entries must be sorted (ascending).
 *
 * Needs the following parameters:
 *
 *   X_Array ..... 1-D numpy histogram array (float32)
 *   Y_Array ..... 1-D numpy histogram array (float32)
 *   X_Samples ... number of samples X is based on (int32)
 *   Y_Samples ... number of samples Y is based on (int32)
 *   Confid. ..... Confidence level (float32)
 *
 * It returns the following variables:
 *
 *   V ... KP test statistic
 *   L ... Significance level
 */
static PyObject* kp_histogram(PyObject* self, PyObject* args)
{
  /* init wrapper */
  PyArrayObject *x_array;
  PyArrayObject *y_array;
  NpyIter *x_iter;
  NpyIter *y_iter;
  int res = -1;
  int nx;
  int ny;
  float c;
  float dp;
  float dm;
  float v;
  float l;

  /*  parse single numpy array argument */
  if (!PyArg_ParseTuple(args, "O!O!iif", &PyArray_Type, &x_array, &PyArray_Type, &y_array, &nx, &ny, &c)) {
    PyErr_SetString(PyExc_Exception, "Could not parse input arguments!");
    goto result;
  }
  if (c <= 0.0 || c >= 1.0) {
    PyErr_SetString(PyExc_Exception, "Confidence level is out of bounds (0 < c < 1)!");
    goto result;
  }
  if (nx <= 0 || ny <= 0) {
    PyErr_SetString(PyExc_Exception, "Number of samples is invalid (nx,ny <= 0)!");
    goto result;
  }

  /* check array lengths */
  int nex = (int)PyArray_SIZE(x_array);
  int ney = (int)PyArray_SIZE(y_array);
  if (nex <= 0 || ney <= 0) {
    PyErr_SetString(PyExc_Exception, "Input arrays have invalid size (e.g. empty)!");
    goto result;
  }
  if (nex != ney) {
    PyErr_SetString(PyExc_Exception, "Input arrays have different size!");
    goto result;
  }

  /*  create iterators */
  x_iter = NpyIter_New(x_array, NPY_ITER_READONLY, NPY_KEEPORDER, NPY_NO_CASTING, NULL);
  if (x_iter == NULL) {
    PyErr_SetString(PyExc_Exception, "Could not create iterator for first array!");
    goto result;
  }
  y_iter = NpyIter_New(y_array, NPY_ITER_READONLY, NPY_KEEPORDER, NPY_NO_CASTING, NULL);
  if (y_iter == NULL) {
    PyErr_SetString(PyExc_Exception, "Could not create iterator for second array!");
    NpyIter_Deallocate(x_iter);
    goto result;
  }
  float ** x_dataptr = (float **) NpyIter_GetDataPtrArray(x_iter);
  float ** y_dataptr = (float **) NpyIter_GetDataPtrArray(y_iter);

  /* KP test */
  res = kuipertest_kp_hist(nex, x_dataptr[0], y_dataptr[0], nx, ny, c, &dp, &dm, &v, &l);

  /* clean up Numpy */
  NpyIter_Deallocate(x_iter);
  NpyIter_Deallocate(y_iter);

  /* return statistics */
result:
  if (res < 0)
    return NULL;
  else if (res > 0)
    return Py_BuildValue("ff", NPY_NAN, NPY_NAN);
  else
    return Py_BuildValue("ff", v, l);
}

/************************************************************************/
 
/***
 * Define function in module.
 */
static PyMethodDef kuipertest_methods[] =
{
  {"kp_histogram", kp_histogram, METH_VARARGS, "Calculates the Kuiper \
    test statistic of two discrete histogram arrays (float32)."},
  {NULL, NULL, 0, NULL}
};

/**
 * Resolve compatibility issues between Python2 and Python3:
 * http://python3porting.com/cextensions.html
 */
#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "kuipertest",        /* m_name */
        "kuipertest",        /* m_doc */
        -1,                  /* m_size */
        kuipertest_methods,  /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };
#endif

#if PY_MAJOR_VERSION >= 3
# define MODULE_MAIN PyInit_kuipertest
#else
# define MODULE_MAIN initkuipertest
#endif

PyMODINIT_FUNC MODULE_MAIN(void)
{
#if PY_MAJOR_VERSION >= 3
    PyObject *m;
    m = PyModule_Create(&moduledef);
    _import_array();
    return m;
#else
    Py_InitModule("kuipertest", kuipertest_methods);
    import_array();
#endif
}

