// src/components/CveDataTable.jsx
import React from "react";
import DataTable from "react-data-table-component";
import { Link } from "react-router-dom";

const getCvssSeverityClasses = (severity) => {
    const s = (severity || "").toLowerCase();
  
    if (s === "critical") return "bg-red-600 text-white border-red-700";
    if (s === "high") return "bg-red-200 text-red-800 border-red-300";
    if (s === "medium") return "bg-yellow-200 text-yellow-800 border-yellow-300";
    if (s === "low") return "bg-green-200 text-green-800 border-green-300";
  
    return "bg-gray-200 text-gray-700 border-gray-300"; // unknown
  };
  

const getStatusClasses = (status) => {
  const s = (status || "").toLowerCase();
  if (s === "deferred") {
    return "bg-yellow-100 text-yellow-700 border-yellow-300";
  }
  if (s === "open") {
    return "bg-red-100 text-red-700 border-red-300";
  }
  if (s === "fixed" || s === "resolved") {
    return "bg-green-100 text-green-700 border-green-300";
  }
  return "bg-gray-100 text-gray-700 border-gray-300";
};

const columns = [
  {
    id: "cve_id",
    name: "CVE ID",
    selector: (row) => row.cve_id,
    sortable: true,
    wrap: true,
    cell: (row) => (
      <Link
        to={`/cve/${row.cve_id}`}
        className="text-blue-600 hover:underline font-medium"
      >
        {row.cve_id}
      </Link>
    ),
  },
  {
    id: "cvss",
    name: "CVSS",
    selector: (row) => row.cvss_score || "—",
    sortable: true,
    wrap: true,
    cell: (row) => (
      <span className="font-semibold text-purple-700">
        {row.cvss_score ?? "—"}
      </span>
    ),
  },
  {
    id: "cvss_severity",
    name: "CVSS Severity",
    selector: (row) => row.cvss_severity || "Unknown",
    sortable: true,
    cell: (row) => (
      <span
        className={`px-2 py-1 text-xs rounded-full border font-semibold
            flex items-center justify-center   w-24                       
            ${getCvssSeverityClasses(row.cvss_severity)}
        `}
      >
        {row.cvss_severity || "Unknown"}
      </span>
    ),
  },
  {
    id: "published",
    name: "Published",
    selector: (row) => row.published || "",
    sortable: true,
    wrap: true,
  },
  {
    id: "status",
    name: "Status",
    selector: (row) => row.status || "Unknown",
    sortable: true,
    cell: (row) => (
      <span
        className={`px-2 py-1 text-xs rounded-full border font-semibold ${getStatusClasses(
          row.status
        )}`}
      >
        {row.status || "Unknown"}
      </span>
    ),
  },
  {
    id: "source",
    name: "Source",
    selector: (row) => row.source || "—",
    sortable: true,
    wrap: true,
    cell: (row) =>
      row.source ? (
        <span className="text-gray-700">{row.source}</span>
      ) : (
        <span className="text-gray-400">—</span>
      ),
  },
];

const customStyles = {
  header: {
    style: {
      minHeight: "48px",
    },
  },
  headRow: {
    style: {
      backgroundColor: "#f3f4f6",
      borderBottomWidth: "1px",
      borderBottomColor: "#e5e7eb",
    },
  },
  headCells: {
    style: {
      fontWeight: 600,
      color: "#374151",
      fontSize: "0.875rem",
    },
  },
  rows: {
    style: {
      fontSize: "0.875rem",
      "&:not(:last-of-type)": {
        borderBottomWidth: "1px",
        borderBottomColor: "#e5e7eb",
      },
    },
    highlightOnHoverStyle: {
      backgroundColor: "#eff6ff",
      transitionDuration: "150ms",
      transitionProperty: "background-color",
    },
  },
  cells: {
    style: {
      paddingTop: "0.75rem",
      paddingBottom: "0.75rem",
      paddingLeft: "1rem",
      paddingRight: "1rem",
    },
  },
  pagination: {
    style: {
      borderTopWidth: "1px",
      borderTopColor: "#e5e7eb",
    },
  },
};

export default function CveDataTable({ data, loading }) {
  return (
    <DataTable
      title={null} // title handled in page header
      columns={columns}
      data={data}
      progressPending={loading}
      pagination                            // ⭐ enables pagination
      paginationPerPage={20}               // ⭐ default rows per page
      paginationRowsPerPageOptions={[10, 20, 50, 100]} // ⭐ dropdown
      highlightOnHover
      striped
      dense
      responsive
      defaultSortFieldId="published"   
      defaultSortAsc={false}
      customStyles={customStyles}
      noDataComponent={
        <div className="py-6 text-gray-500 text-sm">
          No CVEs match your search.
        </div>
      }
    />
  );
}
