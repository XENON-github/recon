# bash completion for recon
_recon() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"
    local opts="-pCT -pAT -pCU -pAU -p -sT -sS -sV --no-sV -O -os -A -4 -6 -t -iL --max-hosts --profile
        --intensity --no-tls-inspect --no-adaptive --rate --max-inflight --workers --timeout --probe-timeout --banner-wait
        --retries --json --csv -o --show-open-filtered -q --quiet --fail-on-open --dry-run --baseline --color
        --progress --no-progress --version -h --help"
    case "$prev" in
        --profile) COMPREPLY=($(compgen -W "quick standard full stealth" -- "$cur")); return ;;
        --color) COMPREPLY=($(compgen -W "auto always never" -- "$cur")); return ;;
        -o|--output|-iL|--input-list|--baseline) COMPREPLY=($(compgen -f -- "$cur")); return ;;
    esac
    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
}
complete -F _recon recon
