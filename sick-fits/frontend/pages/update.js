import UpdateItem from "../components/UpdateItem";
import { Query } from "react-apollo";

const Sell = ({ query }) => (
  <div>
    <UpdateItem id={query.id} />
  </div>
);

export default Sell;
