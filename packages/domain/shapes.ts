/* eslint-disable camelcase */
import { sparql } from '@tpluscode/sparql-builder'
import type { Pattern } from '@hydrofoil/labyrinth/lib/query'
import { dash, sh } from '@tpluscode/rdf-ns-builders/strict'
import type { ResourceHook } from '@hydrofoil/labyrinth/resource'
import { hyper_auth } from '@hydrofoil/vocabularies/builders/strict'
import { check } from 'rdf-web-access-control'
import { isNamedNode } from 'is-graph-pointer'
import { toSparql } from 'clownface-shacl-path'
import $rdf from 'rdf-ext'

export function filterByTargetNode({ subject, object }: Pattern) {
  return sparql`{
    ${subject} ${sh.targetNode} <${object.value}>
  } union {
    <${object.value}> a ?type .
    ${subject} ${sh.targetClass} ?type .
  } union {
    <${object.value}> a ?type .
    ${subject} ${dash.applicableToClass} ?type .
  }`
}

export const removeUnauthorizedProperties: ResourceHook = async (req, pointer) => {
  const controledProps = pointer.any().has(hyper_auth.access)
  if (!req.query.resource) {
    return
  }

  const term = $rdf.namedNode(req.query.resource.toString())

  await Promise.all(controledProps.map(async (prop) => {
    const accessMode = prop.out(hyper_auth.access)
    if (!isNamedNode(accessMode)) {
      return
    }

    const hasAccess = await check({
      client: req.labyrinth.sparql,
      accessMode: accessMode.term,
      agent: req.agent,
      term,
    })

    if (!hasAccess) {
      req.knossos.log(`Removing property ${prop.out(sh.name).value || toSparql(prop.out(sh.path))}`)
      prop.deleteIn(sh.property)
    }
  }))
}
