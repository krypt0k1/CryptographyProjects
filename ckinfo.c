/*
 * (C) nCipher Security Limited 2019
 *
 * The copyright in this software is the property of nCipher Security Limited.
 * This software may not be used, sold, licensed, disclosed, transferred, copied,
 * modified or reproduced in whole or in part or in any manner or form other than
 * in accordance with the licence agreement provided with this software or
 * otherwise without the prior written consent of nCipher Security Limited.
 *
 */

/* Uses C_GetSlotList, C_GetSlotInfo, and C_GetTokenInfo
   to describe the available slots and tokens */

#include "cktestutil.h"

static int opt_count = 1;
static int opt_sleep = 0;

static const nfopt options[] = {
  NFOPT_INT('r', "repeat-count", "COUNT", &opt_count, &ir_pos, "repeat count (default 1)."),
  NFOPT_INT('s', "sleep-for", "SECONDS", &opt_sleep, &ir_pos,
            "sleep between repeats (default 0)."),
  CKOPT_LIBPATH(),
  NFOPT_HELPV('V'),
  NFOPT_END,
};

static const nfopt_proginfo proginfo = { "\n$p [--repeat-count=COUNT --sleep-for=SECONDS]",
                                         "$p, " VERSION_TOOL,
                                         "Displays PKCS #11 library, slot, and token information.",
                                         options };

int main(int argc, char **argv)
{
  CK_RV rv;
  CK_ULONG i, islot, nslots, flags;
  CK_SLOT_ID *pslots = NULL;
  CK_INFO linfo;
  CK_SLOT_INFO sinfo;
  CK_TOKEN_INFO tinfo;

  nf_report_ego(argv[0]);
  if (nfopt_parse(&argc, &argv, &nf_report_quis, &proginfo)) return CKR_ARGUMENTS_BAD;
  if (argc) {
    nf_report_usage_exit(&proginfo);
    return CKR_ARGUMENTS_BAD;
  }

  init_func_list(&gFunctionList);

  rv = gFunctionList->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    fprintf(stderr,
            "%s: C_Initialize failed rv = %08lX (%s)\n",
            nf_report_quis,
            rv,
            NFC_errorcode2name(rv));
    return rv;
  }
  for (; opt_count > 0; opt_count--) {
    rv = gFunctionList->C_GetInfo(&linfo);
    if (rv != CKR_OK) {
      fprintf(stderr,
              "%s: C_GetInfo failed rv = %08lX (%s)\n",
              nf_report_quis,
              rv,
              NFC_errorcode2name(rv));
      return rv;
    }

    printf("PKCS#11 library CK_INFO\n");
    printf("       interface version %d.%02d\n",
           linfo.cryptokiVersion.major,
           linfo.cryptokiVersion.minor);
    printf("                   flags %lX\n", linfo.flags);
    printf("          manufacturerID \"");
    for (i = 0; i < sizeof(linfo.manufacturerID); i++) printf("%c", linfo.manufacturerID[i]);
    printf("\"\n");
    printf("      libraryDescription \"");
    for (i = 0; i < sizeof(linfo.libraryDescription); i++)
      printf("%c", linfo.libraryDescription[i]);
    printf("\"\n");
    printf("  implementation version %d.%02d\n\n",
           linfo.libraryVersion.major,
           linfo.libraryVersion.minor);

    rv = gFunctionList->C_GetSlotList(0, NULL_PTR, &nslots);
    if (rv != CKR_OK) {
      fprintf(stderr,
              "%s: C_GetSlotList failed rv = %08lX (%s)\n",
              nf_report_quis,
              rv,
              NFC_errorcode2name(rv));
      return rv;
    }
    pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
    if (!pslots) return CKR_HOST_MEMORY;

    rv = gFunctionList->C_GetSlotList(0, pslots, &nslots);
    if (rv != CKR_OK) {
      fprintf(stderr,
              "%s: C_GetSlotList failed rv = %08lX (%s)\n",
              nf_report_quis,
              rv,
              NFC_errorcode2name(rv));
      return rv;
    }

    for (islot = 0; islot < nslots; islot++) {
      rv = gFunctionList->C_GetSlotInfo(pslots[islot], &sinfo);
      if (rv != CKR_OK) {
        fprintf(stderr,
                "%s: C_GetSlotInfo failed rv = %08lX (%s)\n",
                nf_report_quis,
                rv,
                NFC_errorcode2name(rv));
        return rv;
      }

      printf("slots[%ld] CK_SLOT_INFO\n", islot);

      printf("         slotDescription \"");
      for (i = 0; i < sizeof(sinfo.slotDescription); i++) printf("%c", sinfo.slotDescription[i]);
      printf("\"\n");
      printf("          manufacturerID \"");
      for (i = 0; i < sizeof(sinfo.manufacturerID); i++) printf("%c", sinfo.manufacturerID[i]);
      printf("\"\n");
      printf("                   flags %lX\n", sinfo.flags);

      if (sinfo.flags & CKF_TOKEN_PRESENT) printf("                   flags & CKF_TOKEN_PRESENT\n");
      if (sinfo.flags & CKF_REMOVABLE_DEVICE)
        printf("                   flags & CKF_REMOVABLE_DEVICE\n");
      if (sinfo.flags & CKF_HW_SLOT) printf("                   flags & CKF_HW_SLOT\n");

      flags = (sinfo.flags & ~(CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE | CKF_HW_SLOT));
      if (flags) printf("         unknown flags %lX\n", flags);

      printf("        hardware version %d.%02d\n",
             sinfo.hardwareVersion.major,
             sinfo.hardwareVersion.minor);
      printf("        firmware version %d.%02d\n",
             sinfo.firmwareVersion.major,
             sinfo.firmwareVersion.minor);

      printf("\n\n");

      if (!(sinfo.flags & CKF_TOKEN_PRESENT)) {
        printf("slots[%ld] Token not present\n", islot);
        rv = gFunctionList->C_GetTokenInfo(pslots[islot], &tinfo);
        if (rv != CKR_TOKEN_NOT_PRESENT) {
          fprintf(stderr,
                  "C_GetSlotInfo doesn't set CKF_TOKEN_PRESENT, "
                  "but C_GetTokenInfo returns %08lX (%s)\n",
                  rv,
                  NFC_errorcode2name(rv));
        }
      } else {
        rv = gFunctionList->C_GetTokenInfo(pslots[islot], &tinfo);
        if (rv != CKR_OK) {
          printf("C_GetTokenInfo failed rv = %08lX (%s)\n", rv, NFC_errorcode2name(rv));
          if (rv != CKR_TOKEN_NOT_RECOGNIZED) {
            if (tinfo.flags & CKF_WRITE_PROTECTED) printf("   (flags & CKF_WRITE_PROTECTED)\n");
            continue;
          }
        }
        printf("slots[%ld] CK_TOKEN_INFO\n", islot);

        printf("                   label \"");
        for (i = 0; i < sizeof(tinfo.label); i++) printf("%c", tinfo.label[i]);
        printf("\"\n");
        printf("          manufacturerID \"");
        for (i = 0; i < sizeof(tinfo.manufacturerID); i++) printf("%c", tinfo.manufacturerID[i]);
        printf("\"\n");
        printf("                   model \"");
        for (i = 0; i < sizeof(tinfo.model); i++) printf("%c", tinfo.model[i]);
        printf("\"\n");
        printf("            serialNumber \"");
        for (i = 0; i < sizeof(tinfo.serialNumber); i++) printf("%c", tinfo.serialNumber[i]);
        printf("\"\n");

        printf("                   flags %lX\n", tinfo.flags);
        if (tinfo.flags & CKF_TOKEN_INITIALIZED)
          printf("                   flags & CKF_TOKEN_INITIALIZED\n");
        if (tinfo.flags & CKF_RNG) printf("                   flags & CKF_RNG\n");
        if (tinfo.flags & CKF_WRITE_PROTECTED)
          printf("                   flags & CKF_WRITE_PROTECTED\n");
        if (tinfo.flags & CKF_LOGIN_REQUIRED)
          printf("                   flags & CKF_LOGIN_REQUIRED\n");
        if (tinfo.flags & CKF_USER_PIN_INITIALIZED)
          printf("                   flags & CKF_USER_PIN_INITIALIZED\n");
        if (tinfo.flags & CKF_RESTORE_KEY_NOT_NEEDED)
          printf("                   flags & CKF_RESTORE_KEY_NOT_NEEDED\n");
        if (tinfo.flags & CKF_CLOCK_ON_TOKEN)
          printf("                   flags & CKF_CLOCK_ON_TOKEN\n");
        if (tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
          printf("                   flags & CKF_PROTECTED_AUTHENTICATION_PATH\n");
        if (tinfo.flags & CKF_DUAL_CRYPTO_OPERATIONS)
          printf("                   flags & CKF_DUAL_CRYPTO_OPERATIONS\n");

        flags = (tinfo.flags &
                 ~(CKF_TOKEN_INITIALIZED | CKF_RNG | CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED |
                   CKF_USER_PIN_INITIALIZED | CKF_RESTORE_KEY_NOT_NEEDED | CKF_CLOCK_ON_TOKEN |
                   CKF_PROTECTED_AUTHENTICATION_PATH | CKF_DUAL_CRYPTO_OPERATIONS));
        if (flags) printf("           unknown flags %lX\n", flags);

        printf("       ulMaxSessionCount ");
        if (tinfo.ulMaxSessionCount == CK_EFFECTIVELY_INFINITE)
          printf("CK_EFFECTIVELY_INFINITE\n");
        else if (tinfo.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulMaxSessionCount);

        printf("     ulMaxRwSessionCount ");
        if (tinfo.ulMaxRwSessionCount == CK_EFFECTIVELY_INFINITE)
          printf("CK_EFFECTIVELY_INFINITE\n");
        else if (tinfo.ulMaxRwSessionCount == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulMaxRwSessionCount);

        printf("             ulMaxPinLen %lu\n", tinfo.ulMaxPinLen);
        printf("             ulMinPinLen %lu\n", tinfo.ulMinPinLen);

        printf("     ulTotalPublicMemory ");
        if (tinfo.ulTotalPublicMemory == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulTotalPublicMemory);
        printf("      ulFreePublicMemory ");
        if (tinfo.ulFreePublicMemory == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulFreePublicMemory);
        printf("    ulTotalPrivateMemory ");
        if (tinfo.ulTotalPrivateMemory == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulTotalPrivateMemory);
        printf("     ulFreePrivateMemory ");
        if (tinfo.ulFreePrivateMemory == CK_UNAVAILABLE_INFORMATION)
          printf("CK_UNAVAILABLE_INFORMATION\n");
        else
          printf("%lu\n", tinfo.ulFreePrivateMemory);

        printf("        hardware version %d.%02d\n",
               tinfo.hardwareVersion.major,
               tinfo.hardwareVersion.minor);
        printf("        firmware version %d.%02d\n",
               tinfo.firmwareVersion.major,
               tinfo.firmwareVersion.minor);
        printf("                 utcTime \"");
        for (i = 0; i < sizeof(tinfo.utcTime); i++) printf("%c", tinfo.utcTime[i]);
        printf("\"\n\n");
      }
    }

    if (opt_sleep && opt_count) sleep(opt_sleep);
  }
  free(pslots);
  rv = gFunctionList->C_Finalize(NULL);
  return rv;
}
