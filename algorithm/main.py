import pandas as pd


def map_mixed_base_severity_configuration(low, medium, high, critical):
    mapping = {
        'CRITICAL': critical,
        'HIGH': high,
        'MEDIUM': medium,
        'LOW': low
    }
    return mapping


def calculate_variable_correlations(dataframe, variables_column, list_of_variables):
    """
    Calculates correlations for each variable separately based on the provided DataFrame.

    Parameters:
    - dataframe: The input DataFrame containing the data.
    - variables_column (str): The column name representing the variables.
    - list_of_variables (list): A list of column names representing the variables of interest.

    Returns:
    - correlation_results (dict): A dictionary containing the correlation matrices for each variable.
    """
    correlation_results = {}
    variables = dataframe[variables_column].dropna().unique()

    for variable in variables:
        # find if there's a column in the dataframe same value as variable
        variable_df = dataframe[dataframe[variables_column] == variable]
        variable_df = variable_df.dropna(subset=list_of_variables)

        correlations = variable_df[list_of_variables].corr()
        average_scores = variable_df[list_of_variables].mean()
        total_num_rows = len(variable_df)

        # Store the item into dict
        correlation_results[variable] = {"correlations": correlations,
                                         "average_scores": average_scores,
                                         "total_num_rows": total_num_rows}

        # print(f"Correlations for Variable: {variable}")
        # print(correlations)
        # print('\n')
        # print(f"Average Scores for Variable: {variable}")
        # print(average_scores)
        # print('\n')
        # print(f"Data Counts for Variable: {variable}")
        # print(data_counts)
        # print('\n')

    return correlation_results


# configuration
pd.set_option('display.max_rows', None)  # Set to None to display all rows
pd.set_option('display.max_columns', None)  # Set to None to display all columns
MAP_Mixed_baseSeverity = map_mixed_base_severity_configuration(2.5, 5, 7.5, 10)
variables_of_interest = ['Mixed_exploitabilityScore', 'Mixed_impactScore', 'Mixed_baseSeverity', 'Mixed_basedScore']

print("Please wait, loading dataframe")
# Assuming your Excel file is named 'filename.xlsx' and contains only one sheet
df = pd.read_excel('../dataset/updated_cve_2023_07_09.xlsx')
print("Complete loading dataframe!")

# Map the value to the word
df['Mixed_baseSeverity'] = df['Mixed_baseSeverity'].map(MAP_Mixed_baseSeverity)

# Removing all cell which is empty and '0'
filtered_df = df[(df[variables_of_interest] != 0).dropna().all(axis=1)]

# Display the DataFrame
# pearson_corr = filtered_df[['Mixed_exploitabilityScore', 'Mixed_impactScore', 'Mixed_baseSeverity', 'Mixed_basedScore']].corr(method='pearson')
# print("Pearson correlation:", pearson_corr)


# Assuming df is your DataFrame and 'vendor' is the column representing vendors
results = calculate_variable_correlations(filtered_df, 'vulnerability', variables_of_interest)

# Access the correlation results for all variables_of_interest
print(results)

# Access the correlation results for a specific vendor
# print(results['redhat'])
