import networkx as nx


def build_attack_graph(events):

    G = nx.DiGraph()

    for i, event in enumerate(events):

        node_label = f"{event['attack_stage']} | {event['technique_name']}"

        G.add_node(i, label=node_label)

        if i > 0:
            G.add_edge(i-1, i)

    return G