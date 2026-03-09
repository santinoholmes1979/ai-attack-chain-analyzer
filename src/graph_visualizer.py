import matplotlib.pyplot as plt
import networkx as nx


def visualize_graph(G):

    pos = nx.spring_layout(G)

    labels = nx.get_node_attributes(G, "label")

    nx.draw(
        G,
        pos,
        labels=labels,
        with_labels=True,
        node_color="lightblue",
        node_size=3000,
        font_size=8
    )

    plt.title("Attack Chain Graph")
    plt.show()