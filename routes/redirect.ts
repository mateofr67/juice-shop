/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function performRedirect() {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string;

    // Definir los dominios permitidos para la redirección
    const allowedDomains = [
      "https://explorer.dash.org",
      "https://blockchain.info",
      "https://etherscan.io"
    ];

    // Comprobar si la URL proporcionada comienza con uno de los dominios permitidos
    const isAllowedDomain = allowedDomains.some(domain => toUrl.startsWith(domain));

    if (isAllowedDomain) {
      // Realizar la redirección si la URL es válida
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || 
               toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || 
               toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6';
      });
      challengeUtils.solveIf(challenges.redirectChallenge, () => {
        return isUnintendedRedirect(toUrl);
      });
      res.redirect(toUrl);
    } else {
      // Si no es un dominio permitido, enviar un error 406 (Not Acceptable)
      res.status(406).json({
        error: 'Unrecognized target URL for redirect: ' + toUrl
      });
    }
  }
};

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
