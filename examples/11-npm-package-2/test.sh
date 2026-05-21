#!/bin/bash
# test.sh — esegue ogni route più volte per permettere a V8 di
# JIT-compilare le funzioni dei pacchetti npm.
# La prima chiamata potrebbe non essere attribuita correttamente
# (funzioni ancora in Ignition, non nel perf map).
# Dalla seconda in poi l'attribuzione dovrebbe essere stabile.

HOST="http://localhost:3001"
ROUNDS=3

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         NodeLeash — Test Routes                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Ogni route viene chiamata ${ROUNDS} volte."
echo "Aspetta che NodeLeash sia avviato prima di procedere."
echo ""
read -p "Premi INVIO per iniziare..."

routes=("files" "outbound" "crypto" "dns" "db" "all")

for route in "${routes[@]}"; do
    echo ""
    echo "──────────────────────────────────────────"
    echo "  Route: /${route}"
    echo "──────────────────────────────────────────"
    for i in $(seq 1 $ROUNDS); do
        echo "  [${i}/${ROUNDS}] curl ${HOST}/${route}"
        result=$(curl -s "${HOST}/${route}")
        echo "  → $(echo "$result" | head -c 80)..."
        sleep 0.5
    done
done

echo ""
echo "✅ Tutte le route completate."
echo "Ferma NodeLeash con Ctrl+C per vedere la policy generata."