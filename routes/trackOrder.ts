/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

module.exports = function trackOrder () {
  return (req: Request, res: Response) => {
    // Asegurarse de que el id no contenga caracteres no válidos
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge)
      ? String(req.params.id).replace(/[^\w-]+/g, '') 
      : req.params.id;

    // Validar si la URL contiene un posible XSS
    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => {
      return utils.contains(id, '<iframe src="javascript:alert(`xss`)">');
    });

    // Usar un filtro seguro para la consulta en lugar de usar $where dinámico
    db.ordersCollection
      .find({ orderId: id })  // Se pasa el id como parte del filtro directo
      .then((order: any) => {
        const result = utils.queryResultToJson(order);
        
        // Comprobar si la consulta retornó más de un resultado
        challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { 
          return result.data.length > 1; 
        });

        // Si no hay resultados, asignar un valor predeterminado
        if (result.data[0] === undefined) {
          result.data[0] = { orderId: id };
        }

        // Responder con los resultados de la consulta
        res.json(result);
      })
      .catch(() => {
        // Manejo de errores si la consulta falla
        res.status(400).json({ error: 'Wrong Param' });
      });
  }
}


// module.exports = function trackOrder () {
//   return (req: Request, res: Response) => {
//     const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : req.params.id

//     challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
//     db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
//       const result = utils.queryResultToJson(order)
//       challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
//       if (result.data[0] === undefined) {
//         result.data[0] = { orderId: id }
//       }
//       res.json(result)
//     }, () => {
//       res.status(400).json({ error: 'Wrong Param' })
//     })
//   }
// }
