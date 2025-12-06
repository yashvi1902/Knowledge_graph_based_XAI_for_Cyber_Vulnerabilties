export default function StatCard({ label, value, onClick, active }) {
    return (
      <button
        onClick={onClick}
        className={`w-full text-left bg-white border rounded-xl px-5 py-4 shadow transition 
          ${active ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:border-blue-300"}
        `}
      >
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-3xl font-bold text-gray-800 mt-1">{value}</p>
      </button>
    );
  }
  