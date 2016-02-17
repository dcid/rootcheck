/* @(#) $Id: ./src/config/integrator-config.h, 2014/05/10 dcid Exp $
 */

/* Copyright (C) 2014 Daniel B. Cid
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
 

#ifndef _CINTEGRATORCONFIG__H
#define _CINTEGRATORCONFIG__H


/* Integrator Config Structure */
typedef struct _IntegratorConfig
{
    unsigned int level;
    unsigned int enabled;
    unsigned int *rule_id; /* array, ending with a 0 */

    char *name;
    char *apikey;
    char *hookurl;
    char *path;
    OSMatch *group;
    OSMatch *location;
}IntegratorConfig;



#endif
