const flows = {
  "Register Device": [
    "Client → Gateway",
    "Validate Device ID",
    "Store RSA Public Key",
    "Persist Device in DB",
    "Create Audit Log"
  ],
  "Issue Token": [
    "Validate Device",
    "Generate JWT",
    "Bind JTI",
    "Store JTI in Redis",
    "Create Audit Log"
  ],
  "Protected Resource": [
    "Receive JWT",
    "Verify Signature",
    "Validate Expiry",
    "Check JTI in Redis",
    "Grant / Deny Access"
  ],
  "Rotate Token": [
    "Validate Old Token",
    "Check JTI Replay",
    "Generate New JWT",
    "Blacklist Old JTI",
    "Audit Log Entry"
  ]
};

export default function FlowViewer({ endpoint }) {
  return (
    <div className="bg-blue-950 p-4 rounded-xl">
      <h2 className="text-xl font-semibold mb-4">
        Flow: {endpoint}
      </h2>

      <ul className="space-y-2">
        {flows[endpoint].map((step, index) => (
          <li key={index} className="bg-blue-900 p-2 rounded-lg">
            {step}
          </li>
        ))}
      </ul>
    </div>
  );
}