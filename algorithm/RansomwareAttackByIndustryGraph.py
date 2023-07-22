import openpyxl
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
file = "Dataset/Copy_of_Ransomware_Attacks.xlsx"

def run():

    """
    Generate a network graph to show the connections between industries and ransomware attacks.

    Parameters:
    - file (str): The path to the Excel file containing industry and ransomware data.

    Returns:
    - plt (matplotlib.pyplot): The matplotlib figure showing the network graph.
    """

    G = nx.Graph()
    ransomware_industry = []
    industry_nodes = set()

    # Open the workbook using openpyxl
    book = openpyxl.load_workbook(file)
    sheet = book.worksheets[0]  # Assuming you want the first sheet (index 0)

    for row in sheet.iter_rows(min_row=2, values_only=True):
        industry = row[3]
        ransomware = row[17]
        if industry and ransomware:  # Check if both values are not empty
            ransomware_industry.append((industry, ransomware))
            industry_nodes.add(industry)

    G.add_edges_from(ransomware_industry)

    # Compute node sizes based on degree (number of connections)
    node_sizes = [100 * G.degree(node) for node in G.nodes]

    # Compute edge widths based on frequency of connections
    edge_widths = defaultdict(int)
    for edge in G.edges:
        edge_widths[edge] += 1
    edge_widths = [edge_widths[edge] for edge in G.edges]

    # Compute node colors
    node_colors = ["green" if node in industry_nodes else "red" for node in G.nodes]

    # Compute layout
    pos = nx.kamada_kawai_layout(G, scale=100)

    # Draw the graph
    plt.figure(figsize=(20, 20), dpi= 100)  # adjust as necessary
    plt.title("Industry Targeted by Each Ransomware Attacks", fontsize=20, fontweight=0, color='purple', loc='center', style='italic')

    nx.draw_networkx_edges(G, pos, alpha=0.4, width=edge_widths)  # draw edges with a bit of transparency and width based on frequency
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes)  # draw nodes with size based on degree

    # Draw labels with specified font size
    nx.draw_networkx_labels(G, pos, font_size=16)

    # Add a legend
    green_patch = plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=15)
    red_patch = plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=15)
    plt.legend([green_patch, red_patch], ['Industry', 'Ransomware Attack'], loc='upper right',fontsize=20)

    return plt


#run().show()