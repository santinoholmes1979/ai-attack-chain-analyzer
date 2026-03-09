from src.loader import load_events
from src.normalizer import normalize_events
from src.chain_builder import build_attack_chain
from src.summarizer import summarize_chain
from src.attack_graph import build_attack_graph
from src.graph_visualizer import visualize_graph
from src.attack_scorer import score_attack_chain, confidence_label
from src.reasoner import reason_about_chain


def main():
    events = load_events("data/sample_attack_chain.json")
    normalized = normalize_events(events)
    chain = build_attack_chain(normalized)

    summary = summarize_chain(chain)
    score = score_attack_chain(chain)
    label = confidence_label(score)
    reasoning = reason_about_chain(chain)

    print("\n=== AI Attack Chain Analyzer ===\n")
    print(summary)

    print("")
    print(f"Attack Confidence: {label} ({score})")
    print(f"Threat Model: {reasoning['threat_model']}")
    print("")

    if reasoning["findings"]:
        print("Key Findings:")
        for finding in reasoning["findings"]:
            print(f"- {finding}")

    graph = build_attack_graph(chain)
    visualize_graph(graph)


if __name__ == "__main__":
    main()